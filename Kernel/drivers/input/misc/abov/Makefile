ifeq ($(WT_COMPILE_FACTORY_VERSION),yes)
    ccflags-y := -DFACTORY_VERSION
endif
ifeq ($(TARGET_BUILD_VARIANT),user)
    ccflags-y := -DUSER_VERSION
endif
obj-$(CONFIG_INPUT_ABOV_SAR)    += sxT316.o
