TARGET = ADShare
OBJS = ADShare.o

CFLAGS = -std=gnu99 -O2 -G0 -Wall -Wextra
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

# ADShare 2.0:
# - KUBridge: kuKernelGetModel()
# - LibPspExploit: leitura de IDStorage/Tachyon/Baryon/Pommel em kernel
# Nao usa SystemCtrlForUser nem sctrlHENFindFunctionOnSystem.
LIBS = -losl -lintrafont -lpng -ljpeg -lz \
       -lpspkubridge -lpspexploit \
       -lpspnet_adhoc -lpspnet_adhocctl -lpspnet \
       -lpspwlan -lpsputility -lpsppower -lpsprtc \
       -lpspgum -lpspgu -lpsphprm -lpspumd \
       -lpspaudiolib -lpspaudio -lm

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = ADShare

PSPSDK := $(shell psp-config --pspsdk-path)

include $(PSPSDK)/lib/build.mak
