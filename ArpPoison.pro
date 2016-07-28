TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp
LIBS += -lpcap
LIBS += -L/usr/include/libnet.h
LIBS += -lpthread
