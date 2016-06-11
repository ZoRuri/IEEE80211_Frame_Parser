QT += core
QT -= gui

CONFIG += c++11

TARGET = IEEE80211_Frame_Parser
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

LIBS += -lpcap

SOURCES += main.cpp
