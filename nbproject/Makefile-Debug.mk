#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/src/graylog.o \
	${OBJECTDIR}/src/main.o \
	${OBJECTDIR}/src/mysql.o \
	${OBJECTDIR}/src/ntop.o \
	${OBJECTDIR}/src/ossec.o \
	${OBJECTDIR}/src/pobject.o \
	${OBJECTDIR}/src/sinks.o \
	${OBJECTDIR}/src/suricata.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=-I/usr/include/ -I/usr/include/mysql -I/usr/include/boost -pthread -Wwrite-strings -DBIG_JOINS=1 -fno-strict-aliasing -g -D_REENTERANT -Wno-write-strings -std=gnu++0x
CXXFLAGS=-I/usr/include/ -I/usr/include/mysql -I/usr/include/boost -pthread -Wwrite-strings -DBIG_JOINS=1 -fno-strict-aliasing -g -D_REENTERANT -Wno-write-strings -std=gnu++0x

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-L/usr/lib/mysql -L/usr/local/lib

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/altprobe_github

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/altprobe_github: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/altprobe_github ${OBJECTFILES} ${LDLIBSOPTIONS} -L/usr/lib -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -ldl -lzmq -lconfig -ldaemon -lboost_system -lboost_thread

${OBJECTDIR}/src/graylog.o: src/graylog.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/graylog.o src/graylog.cpp

${OBJECTDIR}/src/main.o: src/main.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/main.o src/main.cpp

${OBJECTDIR}/src/mysql.o: src/mysql.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/mysql.o src/mysql.cpp

${OBJECTDIR}/src/ntop.o: src/ntop.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/ntop.o src/ntop.cpp

${OBJECTDIR}/src/ossec.o: src/ossec.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/ossec.o src/ossec.cpp

${OBJECTDIR}/src/pobject.o: src/pobject.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/pobject.o src/pobject.cpp

${OBJECTDIR}/src/sinks.o: src/sinks.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/sinks.o src/sinks.cpp

${OBJECTDIR}/src/suricata.o: src/suricata.cpp 
	${MKDIR} -p ${OBJECTDIR}/src
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/suricata.o src/suricata.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/altprobe_github

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
