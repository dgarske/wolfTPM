/* keyduplicate.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Example for TPM 2.0 Key Duplication
 *
 * This example demonstrates:
 * 1. Creating a duplicable key (without fixedTPM/fixedParent attributes)
 * 2. Exporting a key using TPM2_Duplicate for backup or migration
 * 3. Importing a duplicated key using TPM2_Import
 *
 * Use cases:
 * - Enterprise key backup and disaster recovery
 * - Key migration between TPMs (device replacement)
 * - Key escrow for compliance requirements
 * - Multi-device key sharing
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER)

#include <examples/keygen/keygen.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

/******************************************************************************/
/* --- BEGIN TPM Key Duplication Example -- */
/******************************************************************************/

/* Duplication blob file format:
 * [4 bytes] public size
 * [public blob]
 * [4 bytes] duplicate size
 * [duplicate blob]
 * [4 bytes] symSeed size
 * [symSeed blob]
 * [4 bytes] encryptionKey size
 * [encryptionKey blob]
 */

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
static int writeDuplicateBlob(const char* filename,
    const TPM2B_PUBLIC* pub,
    const TPM2B_PRIVATE* duplicate,
    const TPM2B_ENCRYPTED_SECRET* symSeed,
    const TPM2B_DATA* encryptionKey)
{
    int rc = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE fp = NULL;
    word32 val;

    fp = XFOPEN(filename, "wb");
    if (fp == XBADFILE) {
        printf("Error opening file %s for write\n", filename);
        return -1;
    }

    /* Write public */
    val = pub->size + sizeof(pub->size);
    if (XFWRITE(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    if (XFWRITE(&pub->size, 1, sizeof(pub->size), fp) != sizeof(pub->size)) {
        rc = -1; goto exit;
    }
    if (XFWRITE(&pub->publicArea, 1, pub->size, fp) != pub->size) {
        rc = -1; goto exit;
    }

    /* Write duplicate */
    val = duplicate->size;
    if (XFWRITE(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    if (XFWRITE(duplicate->buffer, 1, duplicate->size, fp) != duplicate->size) {
        rc = -1; goto exit;
    }

    /* Write symSeed */
    val = symSeed->size;
    if (XFWRITE(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    if (symSeed->size > 0) {
        if (XFWRITE(symSeed->secret, 1, symSeed->size, fp) != symSeed->size) {
            rc = -1; goto exit;
        }
    }

    /* Write encryptionKey */
    val = encryptionKey->size;
    if (XFWRITE(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    if (encryptionKey->size > 0) {
        if (XFWRITE(encryptionKey->buffer, 1, encryptionKey->size, fp) !=
                encryptionKey->size) {
            rc = -1; goto exit;
        }
    }

    printf("Wrote duplication blob to %s\n", filename);

exit:
    if (fp) XFCLOSE(fp);
#else
    (void)filename;
    (void)pub;
    (void)duplicate;
    (void)symSeed;
    (void)encryptionKey;
#endif
    return rc;
}

static int readDuplicateBlob(const char* filename,
    TPM2B_PUBLIC* pub,
    TPM2B_PRIVATE* duplicate,
    TPM2B_ENCRYPTED_SECRET* symSeed,
    TPM2B_DATA* encryptionKey)
{
    int rc = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE fp = NULL;
    word32 val;

    fp = XFOPEN(filename, "rb");
    if (fp == XBADFILE) {
        printf("Error opening file %s for read\n", filename);
        return -1;
    }

    /* Read public */
    if (XFREAD(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    if (XFREAD(&pub->size, 1, sizeof(pub->size), fp) != sizeof(pub->size)) {
        rc = -1; goto exit;
    }
    if (pub->size > sizeof(pub->publicArea)) {
        printf("Public size too large: %d\n", pub->size);
        rc = -1; goto exit;
    }
    if (XFREAD(&pub->publicArea, 1, pub->size, fp) != pub->size) {
        rc = -1; goto exit;
    }

    /* Read duplicate */
    if (XFREAD(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    duplicate->size = (UINT16)val;
    if (duplicate->size > sizeof(duplicate->buffer)) {
        printf("Duplicate size too large: %d\n", duplicate->size);
        rc = -1; goto exit;
    }
    if (XFREAD(duplicate->buffer, 1, duplicate->size, fp) != duplicate->size) {
        rc = -1; goto exit;
    }

    /* Read symSeed */
    if (XFREAD(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    symSeed->size = (UINT16)val;
    if (symSeed->size > sizeof(symSeed->secret)) {
        printf("SymSeed size too large: %d\n", symSeed->size);
        rc = -1; goto exit;
    }
    if (symSeed->size > 0) {
        if (XFREAD(symSeed->secret, 1, symSeed->size, fp) != symSeed->size) {
            rc = -1; goto exit;
        }
    }

    /* Read encryptionKey */
    if (XFREAD(&val, 1, sizeof(val), fp) != sizeof(val)) {
        rc = -1; goto exit;
    }
    encryptionKey->size = (UINT16)val;
    if (encryptionKey->size > sizeof(encryptionKey->buffer)) {
        printf("EncryptionKey size too large: %d\n", encryptionKey->size);
        rc = -1; goto exit;
    }
    if (encryptionKey->size > 0) {
        if (XFREAD(encryptionKey->buffer, 1, encryptionKey->size, fp) !=
                encryptionKey->size) {
            rc = -1; goto exit;
        }
    }

    printf("Read duplication blob from %s\n", filename);

exit:
    if (fp) XFCLOSE(fp);
#else
    (void)filename;
    (void)pub;
    (void)duplicate;
    (void)symSeed;
    (void)encryptionKey;
#endif
    return rc;
}
#endif /* !NO_FILESYSTEM && !NO_WRITE_TEMP_FILES */

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/keygen/keyduplicate [options]\n");
    printf("\nModes:\n");
    printf("  -create          Create a new duplicable key and save as keyblob\n");
    printf("  -export          Export (duplicate) an existing key\n");
    printf("  -import          Import a duplicated key\n");
    printf("\nOptions:\n");
    printf("  -rsa             Use RSA key (default)\n");
    printf("  -ecc             Use ECC key\n");
    printf("  -aes             Use AES parameter encryption\n");
    printf("  -xor             Use XOR parameter encryption\n");
    printf("  -keyblob=file    Key blob file (default: keyblob.bin)\n");
    printf("  -dupblob=file    Duplication blob file (default: dupblob.bin)\n");
    printf("  -newparent=file  New parent public key file for export (optional)\n");
    printf("\nExamples:\n");
    printf("  # Create a duplicable key\n");
    printf("  ./examples/keygen/keyduplicate -create -rsa\n");
    printf("\n");
    printf("  # Export (duplicate) the key\n");
    printf("  ./examples/keygen/keyduplicate -export -keyblob=keyblob.bin "
           "-dupblob=dupblob.bin\n");
    printf("\n");
    printf("  # Import a duplicated key\n");
    printf("  ./examples/keygen/keyduplicate -import -dupblob=dupblob.bin "
           "-keyblob=imported.bin\n");
}

int TPM2_Keyduplicate_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB dupKey;
    WOLFTPM2_SESSION tpmSession;
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    const char* keyBlobFile = "keyblob.bin";
    const char* dupBlobFile = "dupblob.bin";
    int doCreate = 0;
    int doExport = 0;
    int doImport = 0;

    /* Duplication data */
    Duplicate_In dupIn;
    Duplicate_Out dupOut;
    Import_In impIn;
    Import_Out impOut;

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&dupKey, 0, sizeof(dupKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&publicTemplate, 0, sizeof(publicTemplate));
    XMEMSET(&dupIn, 0, sizeof(dupIn));
    XMEMSET(&dupOut, 0, sizeof(dupOut));
    XMEMSET(&impIn, 0, sizeof(impIn));
    XMEMSET(&impOut, 0, sizeof(impOut));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }

    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-create") == 0) {
            doCreate = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-export") == 0) {
            doExport = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-import") == 0) {
            doImport = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-keyblob=",
                XSTRLEN("-keyblob=")) == 0) {
            keyBlobFile = argv[argc-1] + XSTRLEN("-keyblob=");
        }
        else if (XSTRNCMP(argv[argc-1], "-dupblob=",
                XSTRLEN("-dupblob=")) == 0) {
            dupBlobFile = argv[argc-1] + XSTRLEN("-dupblob=");
        }
        else if (argv[argc-1][0] == '-') {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }

        argc--;
    }

    /* Default to create if no mode specified */
    if (!doCreate && !doExport && !doImport) {
        doCreate = 1;
    }

    printf("TPM2.0 Key Duplication Example\n");
    printf("\tMode: %s\n", doCreate ? "Create" : (doExport ? "Export" : "Import"));
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    printf("\tKey Blob: %s\n", keyBlobFile);
    printf("\tDup Blob: %s\n", dupBlobFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed\n");
        goto exit;
    }

    /* Get the SRK for the key hierarchy */
    rc = getPrimaryStoragekey(&dev, &storage, alg);
    if (rc != 0) {
        printf("Failed to get primary storage key\n");
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) {
            printf("Failed to start session\n");
            goto exit;
        }
        printf("Started session: handle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* ============================================================ */
    /* CREATE: Create a new duplicable key                          */
    /* ============================================================ */
    if (doCreate) {
        TPMA_OBJECT attributes;

        printf("\n--- Creating Duplicable Key ---\n");

        /* Key attributes for a duplicable key:
         * - NOT setting TPMA_OBJECT_fixedTPM
         * - NOT setting TPMA_OBJECT_fixedParent
         * This allows the key to be duplicated/migrated */
        if (alg == TPM_ALG_RSA) {
            /* RSA keys can have both decrypt and sign */
            attributes = (
                TPMA_OBJECT_sensitiveDataOrigin |
                TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_decrypt |
                TPMA_OBJECT_sign |
                TPMA_OBJECT_noDA
            );
            rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate, attributes);
        }
        else if (alg == TPM_ALG_ECC) {
            /* ECC keys: ECDSA for signing only (decrypt+sign not compatible) */
            attributes = (
                TPMA_OBJECT_sensitiveDataOrigin |
                TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign |
                TPMA_OBJECT_noDA
            );
            rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate, attributes,
                TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        }
        else {
            rc = BAD_FUNC_ARG;
        }
        if (rc != 0) {
            printf("Failed to get key template\n");
            goto exit;
        }

        printf("Creating new %s duplicable key...\n", TPM2_GetAlgName(alg));
        printf("  Attributes: 0x%08x\n", (unsigned int)attributes);
        printf("  (fixedTPM: %s, fixedParent: %s)\n",
            (attributes & TPMA_OBJECT_fixedTPM) ? "Yes" : "No",
            (attributes & TPMA_OBJECT_fixedParent) ? "Yes" : "No");

        rc = wolfTPM2_CreateKey(&dev, &dupKey, &storage.handle,
            &publicTemplate, NULL, 0);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_CreateKey failed: 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }

        printf("Created duplicable key (pub %d, priv %d bytes)\n",
            dupKey.pub.size, dupKey.priv.size);

    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        rc = writeKeyBlob(keyBlobFile, &dupKey);
        if (rc != 0) {
            printf("Failed to write key blob\n");
            goto exit;
        }
        printf("Saved key blob to %s\n", keyBlobFile);
    #else
        printf("Key Public Blob %d\n", dupKey.pub.size);
        TPM2_PrintBin((const byte*)&dupKey.pub.publicArea, dupKey.pub.size);
        printf("Key Private Blob %d\n", dupKey.priv.size);
        TPM2_PrintBin(dupKey.priv.buffer, dupKey.priv.size);
    #endif
    }

    /* ============================================================ */
    /* EXPORT: Duplicate an existing key for backup/migration       */
    /* ============================================================ */
    if (doExport) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        printf("\n--- Exporting (Duplicating) Key ---\n");

        /* Read the key blob */
        rc = readKeyBlob(keyBlobFile, &dupKey);
        if (rc != 0) {
            printf("Failed to read key blob from %s\n", keyBlobFile);
            goto exit;
        }
        printf("Read key blob: pub %d, priv %d bytes\n",
            dupKey.pub.size, dupKey.priv.size);

        /* Load the key into TPM */
        rc = wolfTPM2_LoadKey(&dev, &dupKey, &storage.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to load key: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;
        }
        printf("Loaded key to handle 0x%x\n", (word32)dupKey.handle.hndl);

        /* TPM2_Duplicate with encryptedDuplication=CLEAR and userWithAuth=SET
         * can use password authorization.
         * Set up password auth for the key (which has empty auth). */
        wolfTPM2_SetAuthHandle(&dev, 0, &dupKey.handle);

        /* Setup duplication parameters */
        dupIn.objectHandle = dupKey.handle.hndl;
        /* Use TPM_RH_NULL for new parent to get an unencrypted duplicate.
         * For secure transport, use another TPM's storage key public here. */
        dupIn.newParentHandle = TPM_RH_NULL;

        /* No inner symmetric encryption for this example.
         * For production, use AES-128-CFB or similar */
        dupIn.symmetricAlg.algorithm = TPM_ALG_NULL;

        /* No encryption key input (TPM will generate if needed) */
        dupIn.encryptionKeyIn.size = 0;

        printf("Duplicating key...\n");
        rc = TPM2_Duplicate(&dupIn, &dupOut);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_Duplicate failed: 0x%x: %s\n", rc,
                TPM2_GetRCString(rc));
            goto exit;
        }

        printf("Key duplicated successfully!\n");
        printf("  Duplicate blob: %d bytes\n", dupOut.duplicate.size);
        printf("  SymSeed: %d bytes\n", dupOut.outSymSeed.size);
        printf("  EncryptionKey: %d bytes\n", dupOut.encryptionKeyOut.size);

        /* Save the duplication blob */
        rc = writeDuplicateBlob(dupBlobFile,
            &dupKey.pub,
            &dupOut.duplicate,
            &dupOut.outSymSeed,
            &dupOut.encryptionKeyOut);
        if (rc != 0) {
            printf("Failed to write duplication blob\n");
            goto exit;
        }

        printf("Duplication blob saved to %s\n", dupBlobFile);
        printf("\nThis blob can be imported to another TPM or used for backup.\n");
    #else
        printf("Filesystem support required for export\n");
        rc = -1;
    #endif
    }

    /* ============================================================ */
    /* IMPORT: Import a previously duplicated key                   */
    /* ============================================================ */
    if (doImport) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        TPM2B_PUBLIC importPub;
        TPM2B_PRIVATE importDup;
        TPM2B_ENCRYPTED_SECRET importSymSeed;
        TPM2B_DATA importEncKey;
        WOLFTPM2_KEYBLOB importedKey;

        XMEMSET(&importPub, 0, sizeof(importPub));
        XMEMSET(&importDup, 0, sizeof(importDup));
        XMEMSET(&importSymSeed, 0, sizeof(importSymSeed));
        XMEMSET(&importEncKey, 0, sizeof(importEncKey));
        XMEMSET(&importedKey, 0, sizeof(importedKey));

        printf("\n--- Importing Duplicated Key ---\n");

        /* Read the duplication blob */
        rc = readDuplicateBlob(dupBlobFile,
            &importPub,
            &importDup,
            &importSymSeed,
            &importEncKey);
        if (rc != 0) {
            printf("Failed to read duplication blob from %s\n", dupBlobFile);
            goto exit;
        }
        printf("Read duplication blob:\n");
        printf("  Public: %d bytes\n", importPub.size);
        printf("  Duplicate: %d bytes\n", importDup.size);
        printf("  SymSeed: %d bytes\n", importSymSeed.size);
        printf("  EncryptionKey: %d bytes\n", importEncKey.size);

        /* Setup import parameters */
        impIn.parentHandle = storage.handle.hndl;
        impIn.objectPublic = importPub;
        impIn.duplicate = importDup;
        impIn.inSymSeed = importSymSeed;
        impIn.encryptionKey = importEncKey;

        /* Match the symmetric algorithm used during duplication */
        impIn.symmetricAlg.algorithm = TPM_ALG_NULL;

        /* Set authorization for the parent */
        wolfTPM2_SetAuthHandle(&dev, 0, &storage.handle);

        printf("Importing key...\n");
        rc = TPM2_Import(&impIn, &impOut);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_Import failed: 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;
        }

        printf("Key imported successfully!\n");
        printf("  New private blob: %d bytes\n", impOut.outPrivate.size);

        /* Create a key blob for the imported key */
        importedKey.pub = importPub;
        importedKey.priv = impOut.outPrivate;

        /* Save the imported key blob */
        rc = writeKeyBlob(keyBlobFile, &importedKey);
        if (rc != 0) {
            printf("Failed to write imported key blob\n");
            goto exit;
        }
        printf("Imported key saved to %s\n", keyBlobFile);

        /* Verify by loading the imported key */
        rc = wolfTPM2_LoadKey(&dev, &importedKey, &storage.handle);
        if (rc == TPM_RC_SUCCESS) {
            printf("Verified: imported key loads successfully (handle 0x%x)\n",
                (word32)importedKey.handle.hndl);
            wolfTPM2_UnloadHandle(&dev, &importedKey.handle);
        }
        else {
            printf("Warning: could not verify imported key: 0x%x\n", rc);
            rc = 0; /* Don't fail the example */
        }
    #else
        printf("Filesystem support required for import\n");
        rc = -1;
    #endif
    }

    printf("\nKey duplication example completed successfully!\n");

exit:
    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &dupKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM Key Duplication Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER */


#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER)
    rc = TPM2_Keyduplicate_Example(NULL, argc, argv);
#else
    printf("KeyDuplicate code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif

