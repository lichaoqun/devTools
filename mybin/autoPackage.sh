#!/bin/bash
#此脚本应放在xxx.xcworkspace 同级目录下


timeInterval=0			#时间间隔
tempTime=`date +%s`		#当前时间戳
fileName=""				#临时文件名
workSpaceName=""		#要打开的工作空间
projectName=""
length=0

echo $PWD

ls

packFunction(){
	read -p "是否继续打包:" var1
	if [[ $var1 != "y" ]]; then
		echo "===========end package==========="
		exit 0
	fi
}

#-------------------查找主工程名称-------------------

for file in *; do
	if [[ $file =~ ".xcworkspace" ]]; then
		workSpaceName=$file
		break
	fi
done
length=${#workSpaceName}
length=$(($length-12))

projectName=${workSpaceName:0:length}

#-------------------xcode项目编译-------------------
read -p "是否需要打开编译项目:" var2
if [[ $var2 == "y" ]]; then
	open $workSpaceName
	read -p "是否编译项目(编译需要时间等待):" var3
	if [[ $var3 == "y" ]]; then
		#编译项目
		xcodebuild build -workspace $workSpaceName -scheme $projectName
		if [[ $? -ne 0 ]]; then
			echo "===============编译失败请查看项目出错原因==============="
			exit 1
		fi
	else
		packFunction
	fi
else
	packFunction
fi


#-------------------删除多余文件-------------------
cd ~

cd Desktop

if [[ ! -d "Payload" ]]; then
	mkdir Payload
fi

filePath=$HOME/Desktop/Payload

cd Payload

read -p "是否删除以前生成的Payload.ipa文件(y/n):" va4
if [[ $va4 == "y" ]]; then

	for file in *; do
		rm -rf $file
	done
else
	for file in *; do
			# time=`date +%H:%M:%S` #当前时间
			timeStamp=`date +%s`
			var=${file:0:7}
			var=$var$timeStamp
			mv $file $var.ipa
		done	
fi

#-------------------寻找项目路径-------------------
cd ~
macName=${HOME##*/}
macName=/Users/$macName/Library/Developer/Xcode/DerivedData

cd $macName

for file in *; do

	if [[ $file =~ $projectName ]]; then
		#文件去重 当前时间-文件修改时间
		modifyTime=`stat -f %c $file`
		# echo "modifyTime====$modifyTime : $file"
		currentTime=`date +%s`
		timeInterval=$((currentTime-modifyTime))
		if [[ $tempTime -gt $timeInterval ]]; then
		fileName=$file
		tempTime=$timeInterval
		fi
	fi
done

macName=$macName/$fileName/Build/Products

cd ~
cd $macName

if [[ -d "Debug-iphoneos" ]]; then
	macName=$macName/Debug-iphoneos
	cd $macName
else
	echo "$macName"
	echo
 	echo "路径出错,请检查路径"
	exit 1
fi


#-------------------生成IPA文件-------------------
cp -R ${projectName}.app $filePath

cd ~

cd Desktop

zip -r Payload.zip Payload
mv Payload.zip Payload.ipa
mv Payload.ipa Payload

#删除Payload.zip  .app
rm -rf Payload.zip

cd Payload
rm -rf ${projectName}.app

echo "-------------$objc pack success!!-----------------"

exit 0



