import sys
sys.path.append("../ISA") 
import ImageSecurityAnalyser

package_list = "./packages"
fsroot = "/usr/bin"

imageSecurityAnalyser = ImageSecurityAnalyser.ImageSecurityAnalyser()
#imageSecurityAnalyser.process_package_list(package_list)
imageSecurityAnalyser.process_fsroot(fsroot)
