#!/bin/bash -i
# inspired by https://github.com/TheCrysp/Hackbuntu
# this has been tested on the following operating systems:
# Ubuntu, CentOS, Archlinux
# this is still in the testing process. Once all machines have been tested I will release a final version.
#
# by ser3n1ty
# reach out to me on twitter: @ser3n1ty
#

identify1(){
sudo cat /etc/os-release | grep "^NAME*" | cut -d '"' -f 2;
}

checkopsys(){
	declare -a AptArray=("Kubuntu" "Xubuntu" "Lubuntu" "Parrot" "Debian" "Mint" "Knoppix" "Deepin" "Ubuntu")
	declare -a PacArray=("Arch" "ArchBang" "ArchLabs" "ArkOS" "Manjaro" "Endeavour")
	declare -a YumArray=("RedHat" "Fedora" "CentOS Linux" "SUSE" "OpenSUSE")
	
	i=0
	while true; do
		if [[ $(identify1) == ${AptArray[$i]} ]]; then
			echo "APT"
			break 2
		elif [[ $(identify1) == ${PacArray[$i]} ]]; then
			echo "PAC"
			break 2
		elif [[ $(identify1) == ${YumArray[$i]} ]]; then
			echo "YUM"
			break 2
		elif [[ ${AptArray[$i]} == "" && ${PacArray[$i]} == "" && ${YumArray[$i]} == "" ]]; then
			echo "Sorry, I cannot identify your OS. Exiting Script..."
			exit 0
		fi
		let "i=i+1"
	done
}

packageman="$(checkopsys)"

updateopsys(){
	if [[ $packageman == "APT" ]]; then
		sudo apt update -y
		sudo apt upgrade -y
	elif [[ $packageman == "PAC" ]]; then
		sudo pacman -Syyu
	elif [[ $packageman == "YUM" ]]; then
		sudo yum update -y
		sudo yum upgrade -y
	fi
}

setpm(){
	if [[ $packageman == "APT" ]]; then
		echo "sudo apt install -y "
	elif [[ $packageman == "PAC" ]]; then
		echo "sudo pacman -Syyu "
	elif [[ $packageman == "YUM" ]]; then
		echo "sudo yum install -y"
	fi
}

install_basic(){
	echo "installing necessary tools";
	$(setpm) wget
	$(setpm) curl
	$(setpm) make
	$(setpm) gcc
	$(setpm) git
	$(setpm) unzip
	echo "done";
}

install_osspec(){
        echo "installing tools based on your package manager";
        if [[ $packageman == "APT" ]]; then
                sudo apt install -y smbclient
                sudo apt install -y dnsutils #for dig
                sudo apt install -y wireshark
                sudo apt install -y default-jdk
                sudo apt install -y python3-pip python-pip
        elif [[ $packageman == "PAC" ]]; then
                sudo pacman -Syyu smbclient
                sudo pacman -Syyu bind #for dig
                sudo pacman -Syyu wireshark-qt wireshark-cli
                sudo pacman -Syyu jdk-openjdk
                sudo pacman -Syyu python-pip python2-pip
        elif [[ $packageman == "YUM" ]]; then
                sudo yum install -y samba-common-tools samba-client
                sudo yum install -y dnsutils
                sudo yum install -y wireshark
                sudo yum install -y python3-pip python-pip
        fi
        echo "done";
}

install_tools(){
	echo "installing additional tools";
	$(setpm) nmap
	$(setpm) nc
	$(setpm) vim
	$(setpm) gdb
	$(setpm) openssh-client
	$(setpm) nikto
	$(setpm) hydra
	$(setpm) sqlmap
	$(setpm) john
	echo "done";
}
install_pr(){
	echo "installing programming languages";
	$(setpm) python3
	$(setpm) python
	$(setpm) clang
	$(setpm) perl
	$(setpm) ruby
	echo "done";
}

install_pymods(){
        echo "installing some python modules";
        pip install crackmapexec
        pip install impacket
        pip install pwntools
        pip install pyyaml
        pip install ldap3
        echo "done";
}

install_rust(){
	echo "installing rust";
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	echo "done";
}

install_go(){
	echo "installing go";
	wget https://golang.org/dl/go1.16.linux-amd64.tar.gz; tar -xzvf go1*; sudo mv go /usr/local; rm go1*;
	printf "export GOPATH=\$HOME/go\nexport GOROOT=/usr/local/go\nexport PATH=/usr/local/sbin/:\$GOPATH/bin:\$GOROOT/bin:\$PATH\n" >> ~/.bashrc;
	echo "done";
}

install_masscan(){
	echo "installing masscan";
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	sudo make
	sudo make install
	cd ..
	rm -rf masscan/
	echo "done";
}

install_pwncat(){
	echo "installing pwncat";
	pip install git+https://github.com/calebstewart/pwncat.git
	echo "done";
}

install_peass(){
	echo "installing privilege escalation scripts suite";
	git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
	sudo mv privilege-escalation-awesome-scripts-suite/ /opt/
	echo "done";
}

install_seclists(){
	echo "installing seclists";
	git clone https://github.com/danielmiessler/SecLists.git
	sudo mv SecLists/ /opt/
	echo "done";
}

install_gef(){
	echo "installing gef"
	bash -c "$(wget http://gef.blah.cat/sh -O -)"
	echo "done";
}

install_wpscan(){
	echo "installing wpscan";
	sudo gem install wpscan
	echo "done";
}

install_ffuf(){
	echo "installing ffuf";
	go get -u github.com/ffuf/ffuf
	echo "done";
}

install_gobuster(){
	echo "installing gobuster";
	go install github.com/OJ/gobuster/v3@latest
	echo "done";
}

install_amass(){
	echo "installing amass";
	go get -v github.com/OWASP/Amass/cmd/amass
	echo "done";
}

install_mimikatz(){
        echo "installing mimikatz";
        cd /opt/
        sudo wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200918-fix/mimikatz_trunk.zip
        sudo unzip mimikatz_trunk.zip
        echo "done";
}

install_sublist3r(){
	echo "installing sublist3r";
	cd/opt/
	sudo git clone https://github.com/aboul3la/Sublist3r.git
	pip3 install -r /opt/Sublist3r/requirements.txt
	sudo ln -sfv /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
	echo "done";
}

install_enum4linux(){
	echo "installing enum4linux";
	cd /opt/
	sudo git clone https://github.com/CiscoCXSecurity/enum4linux
	sudo ln -sfv /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux
	echo "done";
}
install_enum4linux-ng(){
	echo "installing enum4linux-ng";
	cd /opt/
	sudo git clone https://github.com/cddmp/enum4linux-ng
	sudo ln -sfv /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
	echo "done";
}

install_ghidra(){
        echo "installing ghidra";
        cd /opt/
        sudo wget https://ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip
        sudo unzip ghidra_9.2.2_PUBLIC_20201229.zip
        sudo ln -sfv /opt/ghidra_9.2.2_PUBLIC_20201229/ghidraRun /usr/local/bin/ghidra
        echo "done";
}

install_metasploit(){
        echo "installing metasploit";
        cd /opt/
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
        echo "done";
}

install_searchsploit(){
        echo "installing exploitdb";
        cd /opt/
        sudo git clone https://github.com/offensive-security/exploitdb.git
        sudo ln -svf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
        sudo cp -n /opt/exploitdb/.searchsploit_rc ~/
        echo "done";
}

main(){
	checkopsys
	updateopsys
	setpm
	install_basic
	install_osspec
	install_tools
	install_pr
	install_pymods
	install_rust
	install_go
	install_masscan
	install_pwncat
	install_peass
	install_seclists
	install_gef
	install_wpscan
	install_ffuf
	install_gobuster
	install_amass
	install_mimikatz
	install_sublist3r
	install_enum4linux
	install_enum4linux-ng
	install_ghidra
	install_metasploit
	install_searchsploit
}

main
