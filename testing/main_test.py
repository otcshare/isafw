import sys
sys.path.append("../isafw") 
import isafw

package_list = "./packages"
fsroot = "/iot/iot-os/iot-os/build/tmp-glibc/work/intel_corei7_64-iotos-linux/core-image-minimal-initramfs/1.0-r0/rootfs"
kernel_conf = "/iot/iot-os/iot-os/build/tmp-glibc/work-shared/intel-corei7-64/kernel-build-artifacts/.config"
imagebasename = "base"
reportdir = "/home/elena"
http_proxy = "http_proxy=https_proxy=http://proxy.jf.intel.com:911"

imageSecurityAnalyser = isafw.ImageSecurityAnalyser(http_proxy, reportdir)
#imageSecurityAnalyser.process_package_list(package_list, imagebasename)
#imageSecurityAnalyser.process_fsroot(fsroot, imagebasename)
imageSecurityAnalyser.process_kernel_conf(kernel_conf, imagebasename)

pkg = isafw.ISA_package()
pkg.name = "adminutil"
pkg.version = "1.1.19"
pkg.license = ""
pkg.path_to_sources = "/home/elena/Desktop/Test rpms/"
pkg.path_to_spec = "/home/elena/Desktop/Test rpms/"
pkg.patch_files = ['CVE-2015-9945.patch', 'test_CVE-2015-7653-test.patch', 'test_-cve-2015-0494-test.patch'  ]

#imageSecurityAnalyser.process_package_source(pkg)
