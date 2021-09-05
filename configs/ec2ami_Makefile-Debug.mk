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
CND_PLATFORM=GNU-Linux
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
	${OBJECTDIR}/aggalerts.o \
	${OBJECTDIR}/aggnet.o \
	${OBJECTDIR}/aws.o \
	${OBJECTDIR}/cobject.o \
	${OBJECTDIR}/collector.o \
	${OBJECTDIR}/config.o \
	${OBJECTDIR}/controller.o \
	${OBJECTDIR}/crs.o \
	${OBJECTDIR}/filters.o \
	${OBJECTDIR}/hids.o \
	${OBJECTDIR}/ids.o \
	${OBJECTDIR}/loclog.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/misc.o \
	${OBJECTDIR}/netstat.o \
	${OBJECTDIR}/nids.o \
	${OBJECTDIR}/remlog.o \
	${OBJECTDIR}/remstat.o \
	${OBJECTDIR}/scanners.o \
	${OBJECTDIR}/sinks.o \
	${OBJECTDIR}/source.o \
	${OBJECTDIR}/updates.o \
	${OBJECTDIR}/waf.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=-I/usr/include/ -I/usr/include/boost -I/usr/include/hiredis -I/usr/local/include/activemq-cpp-3.10.0/ -I/usr/include/apr-1/ -DBIG_JOINS=1 -D_REENTERANT -g -Wno-write-strings -fno-strict-aliasing -pthread -std=gnu++11
CXXFLAGS=-I/usr/include/ -I/usr/include/boost -I/usr/include/hiredis -I/usr/local/include/activemq-cpp-3.10.0/ -I/usr/include/apr-1/ -DBIG_JOINS=1 -D_REENTERANT -g -Wno-write-strings -fno-strict-aliasing -pthread -std=gnu++11

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-L/usr/local/lib

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/collector

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/collector: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/collector ${OBJECTFILES} ${LDLIBSOPTIONS} -L/usr/lib -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -lz -lm -lrt -ldl -lpthread -lyaml -ldaemon -lactivemq-cpp -lboost_system -lboost_thread -lboost_iostreams -lhiredis -lGeoIP -lboost_filesystem -lboost_regex

${OBJECTDIR}/aggalerts.o: aggalerts.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/aggalerts.o aggalerts.cpp

${OBJECTDIR}/aggnet.o: aggnet.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/aggnet.o aggnet.cpp
	
${OBJECTDIR}/aws.o: aws.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/aws.o aws.cpp

${OBJECTDIR}/cobject.o: cobject.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/cobject.o cobject.cpp

${OBJECTDIR}/collector.o: collector.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/collector.o collector.cpp

${OBJECTDIR}/config.o: config.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/config.o config.cpp

${OBJECTDIR}/controller.o: controller.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/controller.o controller.cpp

${OBJECTDIR}/crs.o: crs.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/crs.o crs.cpp

${OBJECTDIR}/filters.o: filters.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/filters.o filters.cpp

${OBJECTDIR}/hids.o: hids.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/hids.o hids.cpp

${OBJECTDIR}/ids.o: ids.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ids.o ids.cpp

${OBJECTDIR}/loclog.o: loclog.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/loclog.o loclog.cpp

${OBJECTDIR}/main.o: main.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp

${OBJECTDIR}/misc.o: misc.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/misc.o misc.cpp

${OBJECTDIR}/netstat.o: netstat.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/netstat.o netstat.cpp

${OBJECTDIR}/nids.o: nids.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/nids.o nids.cpp

${OBJECTDIR}/remlog.o: remlog.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/remlog.o remlog.cpp

${OBJECTDIR}/remstat.o: remstat.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/remstat.o remstat.cpp
	
${OBJECTDIR}/scanners.o: scanners.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/scanners.o scanners.cpp

${OBJECTDIR}/sinks.o: sinks.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/sinks.o sinks.cpp

${OBJECTDIR}/source.o: source.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/source.o source.cpp

${OBJECTDIR}/updates.o: updates.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/updates.o updates.cpp
	
${OBJECTDIR}/waf.o: waf.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/waf.o waf.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
