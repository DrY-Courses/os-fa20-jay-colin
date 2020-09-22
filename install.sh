#!/bin/bash

SCRIPT=`realpath -s $BASH_SOURCE[0]`
SCRIPTPATH=`dirname $SCRIPT`

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
NC="\033[0m"

run () {
    STATUS=0

    ./.check_reqs.sh
    if [[ $? != 0 ]]; then
        echo 'FATAL: Requirements not met, please follow recommended installation'
        echo 'commands before continuing.'
        return 1
    fi

    # Do *not* write to the bashrc directly. This can create problems when
    # people try to reinstall Pintos.
    printf "${YELLOW}Add the following two lines to the end of your ~/.bashrc:${NC}\n"
    printf "export PINTOS=$SCRIPTPATH\n"
    printf "export PATH=\$PATH:\$PINTOS/utils\n\n"

    printf "${YELLOW}Run the following command:${NC}\n"
    printf "source ~/.bashrc\n\n"

    printf "${YELLOW}Then, re-run this script to make sure qemu is in your path.${NC}\n\n"

    # Install QEMU
    which qemu &> /dev/null
    if [[ $? != 0 ]]; then
        printf 'Symlinking qemu-system-i386 -> qemu ... '
        QEMU_SYSTEM=`which qemu-system-i386`
        QEMU_PATH=`dirname $QEMU_SYSTEM`
        ln -s $QEMU_SYSTEM utils/qemu &> /dev/null

        which qemu &> /dev/null
        if [[ $? != 0 ]]; then
            printf "${RED}failed!${NC}\n"
            STATUS=1
        else
            printf "${GREEN}done.${NC}\n"
        fi
    fi

    if [[ $STATUS != 0 ]]; then
        printf "${RED}Installation unsuccessful.${NC}\n"
    else
        printf "${GREEN}Installation successful.${NC}\n"
    fi

    return $STATUS
}

run
