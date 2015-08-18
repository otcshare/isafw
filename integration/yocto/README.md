Usage
-----

In order to use isafw during the image build, drop the isafw.bbclass
to your target layer class folder, as well as other bb recipes to 
the corresponding recipe folder (recipes-devtools is a good default
location). Then add the following line to your build/conf/local.conf
file:

INHERIT += "isafw"
 
Also, some isafw plugins require network connection, so in case of a
proxy setup please make sure to export http_proxy variable into your 
environment.

In order to produce image reports, you can execute image build 
normally. For example:

bitbake target-image

If you are only interested to produce a report based on packages 
and without building an image, please use:

bitbake -c analyse_sources_all target-image


Logs
----

All isafw plugins by default create their logs under the 
${LOG_DIR}/isafw-report/ directory, where ${LOG_DIR} is a bitbake 
default location for log files. If you wish to change this location, 
please define ISAFW_REPORTDIR variable in your local.conf file. 
