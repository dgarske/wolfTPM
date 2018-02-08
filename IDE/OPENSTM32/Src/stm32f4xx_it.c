/**
 ******************************************************************************
 * @file    stm32f4xx_it.c
 * @brief   Interrupt Service Routines.
 ******************************************************************************
 *
 * COPYRIGHT(c) 2016 STMicroelectronics
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *   3. Neither the name of STMicroelectronics nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************
 */
/* Includes ------------------------------------------------------------------*/
#include "stm32f4xx_hal.h"
#include "stm32f4xx.h"
#include "stm32f4xx_it.h"
#include "cmsis_os.h"

/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/

extern TIM_HandleTypeDef htim1;
extern SPI_HandleTypeDef hspi1;

/******************************************************************************/
/*            Cortex-M4 Processor Interruption and Exception Handlers         */
/******************************************************************************/

/**
 * @brief This function handles Non maskable interrupt.
 */
void NMI_Handler(void) {
	/* USER CODE BEGIN NonMaskableInt_IRQn 0 */

	/* USER CODE END NonMaskableInt_IRQn 0 */
	/* USER CODE BEGIN NonMaskableInt_IRQn 1 */

	/* USER CODE END NonMaskableInt_IRQn 1 */
}

void HardFault_HandlerC(uint32_t *hardfault_args) {
	/* These are volatile to try and prevent the compiler/linker optimizing them
	 away as the variables never actually get used.  If the debugger won't show the
	 values of the variables, make them global my moving their declaration outside
	 of this function. */

	volatile uint32_t stacked_r0;
	volatile uint32_t stacked_r1;
	volatile uint32_t stacked_r2;
	volatile uint32_t stacked_r3;
	volatile uint32_t stacked_r12;
	volatile uint32_t stacked_lr;
	volatile uint32_t stacked_pc;
	volatile uint32_t stacked_psr;
	volatile uint32_t _CFSR;
	volatile uint32_t _HFSR;
	volatile uint32_t _DFSR;
	volatile uint32_t _AFSR;
	volatile uint32_t _BFAR;
	volatile uint32_t _MMAR;

	stacked_r0 = ((uint32_t) hardfault_args[0]);
	stacked_r1 = ((uint32_t) hardfault_args[1]);
	stacked_r2 = ((uint32_t) hardfault_args[2]);
	stacked_r3 = ((uint32_t) hardfault_args[3]);
	stacked_r12 = ((uint32_t) hardfault_args[4]);
	stacked_lr = ((uint32_t) hardfault_args[5]);
	stacked_pc = ((uint32_t) hardfault_args[6]);
	stacked_psr = ((uint32_t) hardfault_args[7]);

	// Configurable Fault Status Register
	// Consists of MMSR, BFSR and UFSR
	_CFSR = (*((volatile uint32_t *) (0xE000ED28)));

	// Hard Fault Status Register
	_HFSR = (*((volatile uint32_t *) (0xE000ED2C)));

	// Debug Fault Status Register
	_DFSR = (*((volatile uint32_t *) (0xE000ED30)));

	// Auxiliary Fault Status Register
	_AFSR = (*((volatile uint32_t *) (0xE000ED3C)));

	// Read the Fault Address Registers. These may not contain valid values.
	// Check BFARVALID/MMARVALID to see if they are valid values
	// MemManage Fault Address Register
	_MMAR = (*((volatile uint32_t *) (0xE000ED34)));
	// Bus Fault Address Register
	_BFAR = (*((volatile uint32_t *) (0xE000ED38)));

	printf("\n\nHard fault handler (all numbers in hex):\n");
	printf("R0 = %lx\n", stacked_r0);
	printf("R1 = %lx\n", stacked_r1);
	printf("R2 = %lx\n", stacked_r2);
	printf("R3 = %lx\n", stacked_r3);
	printf("R12 = %lx\n", stacked_r12);
	printf("LR [R14] = %lx  subroutine call return address\n", stacked_lr);
	printf("PC [R15] = %lx  program counter\n", stacked_pc);
	printf("PSR = %lx\n", stacked_psr);
	printf("CFSR = %lx\n", _CFSR);
	printf("HFSR = %lx\n", _HFSR);
	printf("DFSR = %lx\n", _DFSR);
	printf("AFSR = %lx\n", _AFSR);
	printf("MMAR = %lx\n", _MMAR);
	printf("BFAR = %lx\n", _BFAR);

	// Break into the debugger
	__asm("BKPT #0\n");
}

__attribute__( ( naked ) )
void HardFault_Handler(void) {
	__asm volatile
	(
			" tst lr, #4                                                \n"
			" ite eq                                                    \n"
			" mrseq r0, msp                                             \n"
			" mrsne r0, psp                                             \n"
			" ldr r1, [r0, #24]                                         \n"
			" ldr r2, handler2_address_const                            \n"
			" bx r2                                                     \n"
			" handler2_address_const: .word HardFault_HandlerC          \n"
	);
}

/**
 * @brief This function handles Memory management fault.
 */
void MemManage_Handler(void) {
	/* USER CODE BEGIN MemoryManagement_IRQn 0 */

	/* USER CODE END MemoryManagement_IRQn 0 */
	while (1) {
	}
	/* USER CODE BEGIN MemoryManagement_IRQn 1 */

	/* USER CODE END MemoryManagement_IRQn 1 */
}

/**
 * @brief This function handles Pre-fetch fault, memory access fault.
 */
void BusFault_Handler(void) {
	/* USER CODE BEGIN BusFault_IRQn 0 */

	/* USER CODE END BusFault_IRQn 0 */
	while (1) {
	}
	/* USER CODE BEGIN BusFault_IRQn 1 */

	/* USER CODE END BusFault_IRQn 1 */
}

/**
 * @brief This function handles Undefined instruction or illegal state.
 */
void UsageFault_Handler(void) {
	/* USER CODE BEGIN UsageFault_IRQn 0 */

	/* USER CODE END UsageFault_IRQn 0 */
	while (1) {
	}
	/* USER CODE BEGIN UsageFault_IRQn 1 */

	/* USER CODE END UsageFault_IRQn 1 */
}

/**
 * @brief This function handles Debug monitor.
 */
void DebugMon_Handler(void) {
	/* USER CODE BEGIN DebugMonitor_IRQn 0 */

	/* USER CODE END DebugMonitor_IRQn 0 */
	/* USER CODE BEGIN DebugMonitor_IRQn 1 */

	/* USER CODE END DebugMonitor_IRQn 1 */
}

/**
 * @brief This function handles System tick timer.
 */
void SysTick_Handler(void) {
	/* USER CODE BEGIN SysTick_IRQn 0 */

	/* USER CODE END SysTick_IRQn 0 */
	osSystickHandler();
	/* USER CODE BEGIN SysTick_IRQn 1 */

	/* USER CODE END SysTick_IRQn 1 */
}

/******************************************************************************/
/* STM32F4xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32f4xx.s).                    */
/******************************************************************************/

/**
 * @brief This function handles TIM1 update interrupt and TIM10 global interrupt.
 */
void TIM1_UP_TIM10_IRQHandler(void) {
	/* USER CODE BEGIN TIM1_UP_TIM10_IRQn 0 */

	/* USER CODE END TIM1_UP_TIM10_IRQn 0 */
	HAL_TIM_IRQHandler(&htim1);
	/* USER CODE BEGIN TIM1_UP_TIM10_IRQn 1 */

	/* USER CODE END TIM1_UP_TIM10_IRQn 1 */
}

/**
  * @brief  This function handles SPI interrupt request.
  * @param  None
  * @retval None
  */
void SPI1_IRQHandler(void)
{
  HAL_SPI_IRQHandler(&hspi1);
}


/* USER CODE BEGIN 1 */

/* USER CODE END 1 */
/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
