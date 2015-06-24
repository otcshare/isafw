Image Security Analyser Framework
=================================

The purpose of ISA FW is to provide an extensible framework for analysing different security aspects of images during the build process. The framework supports a number of callbacks (such as process_package_source(), process_fsroot(), and etc.) that are invoked by the build system during different stages of package and image build. These callbacks are then forwarded for processing to the avaliable ISA FW plugins that have registered for these callbacks. Plugins can do their own processing on each stage of the build process and produce security reports. 

Currently supported plugins
---------------------------

 - ISA_cve_plugin. Plugin for checking CVE information for packages. 
   Works on top of cve-check-tool (https://github.com/ikeydoherty/cve-check-tool)
 - ISA_la_plugin. Plugin for verifying licensing information for packages. 
 - ISA_cf_plugin. Plugin for analysing binary compilation flags on rootfs.
   Works on top of checksec.sh script (http://www.trapkit.de/tools/checksec.html)

