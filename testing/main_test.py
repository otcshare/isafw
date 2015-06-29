import sys
from isafw import *

package_list = "./packages"
fsroot = "/usr/bin"
imagebasename = "base"

http_proxy = "http_proxy=https_proxy=http://proxy.jf.intel.com:911"

imageSecurityAnalyser = isafw.ImageSecurityAnalyser(http_proxy)
#imageSecurityAnalyser.process_package_list(package_list)
#imageSecurityAnalyser.process_fsroot(fsroot, imagebasename, "/home/elena")

pkg = isafw.ISA_package()
pkg.name = "adminutil"
pkg.version = "1.1.19"
pkg.license = ""
pkg.path_to_sources = "/home/elena/Desktop/Test rpms/"
pkg.path_to_spec = "/home/elena/Desktop/Test rpms/"
pkg.patch_files = ['CVE-2015-9945.patch', 'test_CVE-2015-9945-test.patch', 'test_-cve-2015-9945-test.patch'  ]

imageSecurityAnalyser.process_package_source(pkg, "/home/elena")
