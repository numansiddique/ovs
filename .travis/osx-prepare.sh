#!/bin/bash
set -ev
pip3 install --user six
pip3 install --user --upgrade docutils

brew update || true
brew uninstall libtool && brew install libtool || true
