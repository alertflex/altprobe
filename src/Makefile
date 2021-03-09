#
#  There exist several targets which are by default empty and which can be 
#  used for execution of your targets. These targets are usually executed 
#  before and after some main targets. They are: 
#
#     .build-pre:              called before 'build' target
#     .build-post:             called after 'build' target
#     .clean-pre:              called before 'clean' target
#     .clean-post:             called after 'clean' target
#     .clobber-pre:            called before 'clobber' target
#     .clobber-post:           called after 'clobber' target
#     .all-pre:                called before 'all' target
#     .all-post:               called after 'all' target
#     .help-pre:               called before 'help' target
#     .help-post:              called after 'help' target
#
#  Targets beginning with '.' are not intended to be called on their own.
#
#  Main targets can be executed directly, and they are:
#  
#     build                    build a specific configuration
#     clean                    remove built files from a configuration
#     clobber                  remove all built files
#     all                      build all configurations
#     help                     print help mesage
#  
#  Targets .build-impl, .clean-impl, .clobber-impl, .all-impl, and
#  .help-impl are implemented in nbproject/makefile-impl.mk.
#
#  Available make variables:
#
#     CND_BASEDIR                base directory for relative paths
#     CND_DISTDIR                default top distribution directory (build artifacts)
#     CND_BUILDDIR               default top build directory (object files, ...)
#     CONF                       name of current configuration
#     CND_PLATFORM_${CONF}       platform name (current configuration)
#     CND_ARTIFACT_DIR_${CONF}   directory of build artifact (current configuration)
#     CND_ARTIFACT_NAME_${CONF}  name of build artifact (current configuration)
#     CND_ARTIFACT_PATH_${CONF}  path to build artifact (current configuration)
#     CND_PACKAGE_DIR_${CONF}    directory of package (current configuration)
#     CND_PACKAGE_NAME_${CONF}   name of package (current configuration)
#     CND_PACKAGE_PATH_${CONF}   path to package (current configuration)
#
# NOCDDL


# Environment 
MKDIR=mkdir
CP=cp
CCADMIN=CCadmin


# build
build: .build-post

.build-pre:
# Add your pre 'build' code here...

.build-post: .build-impl
# Add your post 'build' code here...


# clean
clean: .clean-post

.clean-pre:
# Add your pre 'clean' code here...

.clean-post: .clean-impl
# Add your post 'clean' code here...


# clobber
clobber: .clobber-post

.clobber-pre:
# Add your pre 'clobber' code here...

.clobber-post: .clobber-impl
# Add your post 'clobber' code here...


# all
all: .all-post

.all-pre:
# Add your pre 'all' code here...

.all-post: .all-impl
# Add your post 'all' code here...


# build tests
build-tests: .build-tests-post

.build-tests-pre:
# Add your pre 'build-tests' code here...

.build-tests-post: .build-tests-impl
# Add your post 'build-tests' code here...


# run tests
test: .test-post

.test-pre: build-tests
# Add your pre 'test' code here...

.test-post: .test-impl
# Add your post 'test' code here...


# help
help: .help-post

.help-pre:
# Add your pre 'help' code here...

.help-post: .help-impl
# Add your post 'help' code here...

install:
	cp ./dist/Debug/GNU-Linux/collector /usr/local/bin/altprobe
	chmod u+x ./scripts/altprobe-restart.sh
	chmod u+x ./scripts/altprobe-start.sh
	chmod u+x ./scripts/altprobe-status.sh
	chmod u+x ./scripts/altprobe-stop.sh
	cp ./scripts/altprobe-restart.sh /usr/local/bin/altprobe-restart
	cp ./scripts/altprobe-start.sh /usr/local/bin/altprobe-start
	cp ./scripts/altprobe-stop.sh /usr/local/bin/altprobe-stop
	cp ./scripts/altprobe-status.sh /usr/local/bin/altprobe-status
	
	if [ ! -d "/etc/altprobe" ]; then\
		mkdir /etc/altprobe;\
	fi;
	cp ./etc/filters.json /etc/altprobe
	cp ./etc/altprobe.yaml /etc/altprobe
	
	if [ ! -d "/etc/altprobe/scripts" ]; then\
		mkdir /etc/altprobe/scripts;\
	fi;
	
	chmod u+x ./scripts/rulesup-falco.sh
	chmod u+x ./scripts/rulesup-wazuh.sh
	chmod u+x ./scripts/rulesup-suri.sh
	chmod u+x ./scripts/restart-falco.sh
	chmod u+x ./scripts/restart-wazuh.sh
	chmod u+x ./scripts/restart-suri.sh
	cp ./scripts/rulesup-falco.sh /etc/altprobe/scripts/
	cp ./scripts/rulesup-wazuh.sh /etc/altprobe/scripts/
	cp ./scripts/rulesup-suri.sh /etc/altprobe/scripts/
	cp ./scripts/restart-falco.sh /etc/altprobe/scripts/
	cp ./scripts/restart-wazuh.sh /etc/altprobe/scripts/
	cp ./scripts/restart-suri.sh /etc/altprobe/scripts/
		
update:
	cp ./dist/Debug/GNU-Linux/collector /usr/local/bin/altprobe
	
# include project implementation makefile
include nbproject/Makefile-impl.mk

# include project make variables
include nbproject/Makefile-variables.mk
