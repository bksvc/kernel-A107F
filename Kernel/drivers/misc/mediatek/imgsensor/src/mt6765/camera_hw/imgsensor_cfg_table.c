/*
 * Copyright (C) 2017 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "kd_imgsensor.h"

#include "regulator/regulator.h"
#include "gpio/gpio.h"
/*#include "mt6306/mt6306.h"*/
#include "mclk/mclk.h"



#include "imgsensor_cfg_table.h"

enum IMGSENSOR_RETURN
	(*hw_open[IMGSENSOR_HW_ID_MAX_NUM])(struct IMGSENSOR_HW_DEVICE **) = {
	imgsensor_hw_regulator_open,
	imgsensor_hw_gpio_open,
	/*imgsensor_hw_mt6306_open,*/
	imgsensor_hw_mclk_open
};

struct IMGSENSOR_HW_CFG imgsensor_custom_config[] = {
	{
		IMGSENSOR_SENSOR_IDX_MAIN,
		IMGSENSOR_I2C_DEV_0,
		{
			{IMGSENSOR_HW_ID_MCLK, IMGSENSOR_HW_PIN_MCLK},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_AVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DOVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_AFVDD},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_AF_EN},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_RST},
			{IMGSENSOR_HW_ID_NONE, IMGSENSOR_HW_PIN_NONE},
		},
	},
	{
		IMGSENSOR_SENSOR_IDX_SUB,
		IMGSENSOR_I2C_DEV_1,
		{
			{IMGSENSOR_HW_ID_MCLK, IMGSENSOR_HW_PIN_MCLK},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_AVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DOVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DVDD},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_PDN},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_RST},
			{IMGSENSOR_HW_ID_NONE, IMGSENSOR_HW_PIN_NONE},
		},
	},
	{
		IMGSENSOR_SENSOR_IDX_MAIN2,
		IMGSENSOR_I2C_DEV_2,
		{
			{IMGSENSOR_HW_ID_MCLK, IMGSENSOR_HW_PIN_MCLK},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_AVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DOVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DVDD},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_PDN},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_RST},
			{IMGSENSOR_HW_ID_NONE, IMGSENSOR_HW_PIN_NONE},
		},
	},
	{
		IMGSENSOR_SENSOR_IDX_SUB2,
		IMGSENSOR_I2C_DEV_1,
		{
			{IMGSENSOR_HW_ID_MCLK, IMGSENSOR_HW_PIN_MCLK},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_AVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DOVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DVDD},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_PDN},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_RST},
			{IMGSENSOR_HW_ID_NONE, IMGSENSOR_HW_PIN_NONE},
		},
	},
	{
		IMGSENSOR_SENSOR_IDX_MAIN3,
		IMGSENSOR_I2C_DEV_2,
		{
			{IMGSENSOR_HW_ID_MCLK, IMGSENSOR_HW_PIN_MCLK},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_AVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DOVDD},
			{IMGSENSOR_HW_ID_REGULATOR, IMGSENSOR_HW_PIN_DVDD},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_PDN},
			{IMGSENSOR_HW_ID_GPIO, IMGSENSOR_HW_PIN_RST},
			{IMGSENSOR_HW_ID_NONE, IMGSENSOR_HW_PIN_NONE},
		},
	},

	{IMGSENSOR_SENSOR_IDX_NONE}
};

struct IMGSENSOR_HW_POWER_SEQ platform_power_sequence[] = {
#ifdef MIPI_SWITCH
	{
		IMGSENSOR_SENSOR_IDX_NAME_SUB,
		{
			{
				IMGSENSOR_HW_PIN_MIPI_SWITCH_EN,
				IMGSENSOR_HW_PIN_STATE_LEVEL_0,
				0,
				IMGSENSOR_HW_PIN_STATE_LEVEL_HIGH,
				0
			},
			{
				IMGSENSOR_HW_PIN_MIPI_SWITCH_SEL,
				IMGSENSOR_HW_PIN_STATE_LEVEL_HIGH,
				0,
				IMGSENSOR_HW_PIN_STATE_LEVEL_0,
				0
			},
		}
	},
	{
		IMGSENSOR_SENSOR_IDX_NAME_MAIN2,
		{
			{
				IMGSENSOR_HW_PIN_MIPI_SWITCH_EN,
				IMGSENSOR_HW_PIN_STATE_LEVEL_0,
				0,
				IMGSENSOR_HW_PIN_STATE_LEVEL_HIGH,
				0
			},
			{
				IMGSENSOR_HW_PIN_MIPI_SWITCH_SEL,
				IMGSENSOR_HW_PIN_STATE_LEVEL_0,
				0,
				IMGSENSOR_HW_PIN_STATE_LEVEL_0,
				0
			},
		}
	},
#endif

	{NULL}
};

/* Legacy design */
struct IMGSENSOR_HW_POWER_SEQ sensor_power_sequence[] = {
		//------main sensor------//
#if defined(N8_HI1336_XL_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_HI1336_XL_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1100, 5},
			{AVDD, Vol_2800, 1},
			{AFVDD, Vol_2800, 1},
			{AFVDD_EN, Vol_Low, 0},
			{AFVDD_EN, Vol_High, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
#if defined(N8_HI1336_TXD_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_HI1336_TXD_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1100, 5},
			{AVDD, Vol_2800, 1},
			{AFVDD, Vol_2800, 1},
			{AFVDD_EN, Vol_Low, 0},
			{AFVDD_EN, Vol_High, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
#if defined(N8_S5K3L6_HLT_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_S5K3L6_HLT_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1100, 5},
			{AVDD, Vol_2800, 1},
			{AFVDD, Vol_2800, 1},
			{AFVDD_EN, Vol_Low, 0},
			{AFVDD_EN, Vol_High, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
		//------sub  sensor------//
#if defined(N8_HI846_SHT_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_HI846_SHT_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1200, 1},
			{AVDD, Vol_2800, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
#if defined(N8_HI846_LY_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_HI846_LY_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1200, 1},
			{AVDD, Vol_2800, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
#if defined(N8_GC8034_TXD_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_GC8034_TXD_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1200, 1},
			{AVDD, Vol_2800, 1},
			{SensorMCLK, Vol_High, 0},
			{RST, Vol_Low, 10},
			{RST, Vol_High, 1},
				},
			},
#endif
		//------main2 sensor-----//
#if defined(N8_GC2375H_HLT_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_GC2375H_HLT_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1800, 1},
			{AVDD, Vol_2800, 1},
			{SensorMCLK, Vol_High, 0},
			{PDN, Vol_High, 1},
			{PDN, Vol_Low, 0},
			{RST, Vol_Low, 5},
			{RST, Vol_High, 0}
			},
			},

#endif
#if defined(N8_GC2375A_QH_MIPI_RAW)
			{
			SENSOR_DRVNAME_N8_GC2375A_QH_MIPI_RAW,
			{
			{DOVDD, Vol_1800, 1},
			{DVDD, Vol_1800, 1},
			{AVDD, Vol_2800, 1},
			{SensorMCLK, Vol_High, 0},
			{PDN, Vol_High, 1},
			{PDN, Vol_Low, 0},
			{RST, Vol_Low, 5},
			{RST, Vol_High, 0}
			},
			},

#endif
	/* add new sensor before this line */
	{NULL,},
};

