#!/bin/sh

echo "Building pt-net and pt-host ..."

cd net/ ; make ; mv pt-net ../ ; cd ../
cd host/ ; make ; mv pt-host ../ ; cd ../
