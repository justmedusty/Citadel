#!/bin/sh

echo "This is for a bash env only, if you are running on BSD or similar without bash, you will need to carry out the steps here manually."
sleep 3

cmake -B build
cd build
make

mkdir -p ~/bin
if [[ -z $(cat ~/.bashrc | grep 'PATH=$PATH:~/bin')  ]]; then
	echo 'PATH=$PATH:~/bin' >> ~/.bashrc
fi

cp citadel ~/bin

cd ..
rm -rf build
source ~/.bashrc
echo "citadel has been built and placed in ~/bin, your .bashrc has been updated and sourced and your bash sessions will now be able to call 'citadel' to use the citadel password management tool. Enjoy~"
