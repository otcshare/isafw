import ImageSecurityAnalyser

package_list = "/home/elena/Python/ImageSecurityAnalyser/packages"
fsroot = "/usr/bin"

imageSecurityAnalyser = ImageSecurityAnalyser.ImageSecurityAnalyser()
#imageSecurityAnalyser.process_package_list(package_list)
imageSecurityAnalyser.process_fsroot(fsroot)
