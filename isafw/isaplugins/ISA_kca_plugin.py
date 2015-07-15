#
# ISA_kca_plugin.py -  Kernel config options analyzer plugin, part of ISA FW
#
# Copyright (c) 2015, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Intel Corporation nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

KCAnalyzer = None
fullreport = "/kca_fullreport_"
problemsreport = "/kca_problems_report_"

class ISA_KCA():    
    initialized = False

    hardening_kco = {  'CONFIG_CC_STACKPROTECTOR'                       : 'not set', 
                       'CONFIG_DEFAULT_MMAP_MIN_ADDR'                   : 'not set',
                       'CONFIG_KEXEC'                                   : 'not set',
                       'CONFIG_PROC_KCORE'                              : 'not set',
                       'CONFIG_SECURITY_DMESG_RESTRICT'                 : 'not set',
                       'CONFIG_DEBUG_STACKOVERFLOW'                     : 'not set',
                       'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS'           : 'not set',
                       'CONFIG_ARCH_HAS_DEBUG_STRICT_USER_COPY_CHECKS'  : 'not set',
                       'CONFIG_IKCONFIG_PROC'                           : 'not set',
                       'CONFIG_RANDOMIZE_BASE'                          : 'not set',
                       'CONFIG_RANDOMIZE_BASE_MAX_OFFSET'               : 'not set',
                       'CONFIG_DEBUG_RODATA'                            : 'not set',
                       'CONFIG_STRICT_DEVMEM'                           : 'not set',
                       'CONFIG_DEVKMEM'                                 : 'not set',
                       'CONFIG_X86_MSR'                                 : 'not set',
                       'CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE'           : 'not set',
                       'CONFIG_DEBUG_KERNEL'                            : 'not set',
                       'CONFIG_DEBUG_FS'                                : 'not set'
                     }

    hardening_kco_ref={'CONFIG_CC_STACKPROTECTOR'                       : 'y', 
                       'CONFIG_DEFAULT_MMAP_MIN_ADDR'                   : '65536', # x86 specific
                       'CONFIG_KEXEC'                                   : 'n',
                       'CONFIG_PROC_KCORE'                              : 'n',
                       'CONFIG_SECURITY_DMESG_RESTRICT'                 : 'y',
                       'CONFIG_DEBUG_STACKOVERFLOW'                     : 'y',
                       'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS'           : 'y',
                       'CONFIG_ARCH_HAS_DEBUG_STRICT_USER_COPY_CHECKS'  : 'y',
                       'CONFIG_IKCONFIG_PROC'                           : 'n',
                       'CONFIG_RANDOMIZE_BASE'                          : 'y',
                       'CONFIG_RANDOMIZE_BASE_MAX_OFFSET'               : '0x40000000', # x86 specific
                       'CONFIG_DEBUG_RODATA'                            : 'y',
                       'CONFIG_STRICT_DEVMEM'                           : 'y',
                       'CONFIG_DEVKMEM'                                 : 'n',
                       'CONFIG_X86_MSR'                                 : 'n',
                       'CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE'           : 'y',
                       'CONFIG_DEBUG_KERNEL'                            : 'n',
                       'CONFIG_DEBUG_FS'                                : 'n'
                     }

    keys_kco =       { 'CONFIG_KEYS'                                    : 'not set',
                       'CONFIG_TRUSTED_KEYS'                            : 'not set',
                       'CONFIG_ENCRYPTED_KEYS'                          : 'not set',
                       'CONFIG_KEYS_DEBUG_PROC_KEYS'                    : 'not set'
                     }
    keys_kco_ref =   { 'CONFIG_KEYS'                                    : 'y',
                       'CONFIG_TRUSTED_KEYS'                            : 'y',
                       'CONFIG_ENCRYPTED_KEYS'                          : 'y',
                       'CONFIG_KEYS_DEBUG_PROC_KEYS'                    : 'n'
                     }

    security_kco =   { 'CONFIG_SECURITY'                                : 'not set', 
                       'CONFIG_SECURITYFS'                              : 'not set',
                       'CONFIG_SECURITY_NETWORKING'                     : 'not set',
                       'CONFIG_DEFAULT_SECURITY'                        : 'not set',
                       'CONFIG_SECURITY_SELINUX'                        : 'not set',
                       'CONFIG_SECURITY_SMACK'                          : 'not set',
                       'CONFIG_SECURITY_TOMOYO'                         : 'not set',
                       'CONFIG_SECURITY_APPARMOR'                       : 'not set',
                       'CONFIG_SECURITY_YAMA'                           : 'not set',
                       'CONFIG_SECURITY_YAMA_STACKED'                   : 'not set',
                       'CONFIG_LSM_MMAP_MIN_ADDR'                       : 'not set',
                       'CONFIG_INTEL_TXT'                               : 'not set'                      
                      }

    security_kco_ref ={'CONFIG_SECURITY'                                : 'y', 
                       'CONFIG_SECURITYFS'                              : 'y',
                       'CONFIG_SECURITY_NETWORKING'                     : 'y',
                       'CONFIG_DEFAULT_SECURITY'                        : '"selinux","smack","apparmor","tomoyo"',
                       'CONFIG_SECURITY_SELINUX'                        : 'y',
                       'CONFIG_SECURITY_SMACK'                          : 'y',
                       'CONFIG_SECURITY_TOMOYO'                         : 'y',
                       'CONFIG_SECURITY_APPARMOR'                       : 'y',
                       'CONFIG_SECURITY_YAMA'                           : 'y',
                       'CONFIG_SECURITY_YAMA_STACKED'                   : 'y',
                       'CONFIG_LSM_MMAP_MIN_ADDR'                       : '65536', #x86 specific
                       'CONFIG_INTEL_TXT'                               : 'y'                      
                      }

    integrity_kco =  { 'CONFIG_INTEGRITY'                               : 'not set',
                       'CONFIG_INTEGRITY_SIGNATURE'                     : 'not set',
                       'CONFIG_INTEGRITY_AUDIT'                         : 'not set',
                       'CONFIG_IMA'                                     : 'not set',
                       'CONFIG_IMA_LSM_RULES'                           : 'not set',
                       'CONFIG_IMA_APPRAISE'                            : 'not set',
                       'CONFIG_IMA_TRUSTED_KEYRING'                     : 'not set',
                       'CONFIG_IMA_APPRAISE_SIGNED_INIT'                : 'not set',
                       'CONFIG_EVM'                                     : 'not set',
                       'CONFIG_EVM_ATTR_FSUUID'                         : 'not set',
                       'CONFIG_EVM_EXTRA_SMACK_XATTRS'                  : 'not set',
                       'CONFIG_IMA_DEFAULT_HASH_SHA256'                 : 'not set'
                       }

    integrity_kco_ref={'CONFIG_INTEGRITY'                               : 'y',
                       'CONFIG_INTEGRITY_SIGNATURE'                     : 'y',
                       'CONFIG_INTEGRITY_AUDIT'                         : 'y',
                       'CONFIG_IMA'                                     : 'y',
                       'CONFIG_IMA_LSM_RULES'                           : 'y',
                       'CONFIG_IMA_APPRAISE'                            : 'y',
                       'CONFIG_IMA_TRUSTED_KEYRING'                     : 'y',
                       'CONFIG_IMA_APPRAISE_SIGNED_INIT'                : 'y',
                       'CONFIG_EVM'                                     : 'y',
                       'CONFIG_EVM_ATTR_FSUUID'                         : 'y',
                       'CONFIG_EVM_EXTRA_SMACK_XATTRS'                  : 'y',
                       'CONFIG_IMA_DEFAULT_HASH_SHA256'                 : 'y'
                       }

    def __init__(self, proxy, reportdir):
        self.proxy = proxy
        self.reportdir = reportdir
        self.initialized = True
        print("Plugin ISA_KCA initialized!")

    def process_kernel_conf(self, kernel_conf, imagebasename):
        print("kernel_conf: ", kernel_conf)
        if (self.initialized == True):
          with open(kernel_conf, 'r') as fkernel_conf:
            for line in fkernel_conf:
                line = line.strip('\n')
                for key in self.hardening_kco:
                    if key +'=' in line:
                        self.hardening_kco[key] = line.split('=')[1]
                for key in self.keys_kco:
                    if key +'=' in line:
                        self.keys_kco[key] = line.split('=')[1]
                for key in self.security_kco:
                    if key +'=' in line:
                        self.security_kco[key] = line.split('=')[1]
                for key in self.integrity_kco:
                    if key +'=' in line:
                        self.integrity_kco[key] = line.split('=')[1]
          print("hardening_kco: " + str(self.hardening_kco))     
          print("keys_kco: " + str(self.keys_kco))              
          print("security_kco: " + str(self.security_kco))              
          print("integrity_kco: " + str(self.integrity_kco))                       
          with open(self.reportdir + fullreport + imagebasename, 'w') as freport:
                freport.write("Report for image: " + imagebasename + '\n')
                freport.write("With the kernel conf at: " + kernel_conf + '\n\n')
                freport.write("Hardening options:\n")
                for key in sorted(self.hardening_kco):
                    freport.write(key + ' : ' + str(self.hardening_kco[key]) + '\n')
                freport.write("\nKey-related options:\n")
                for key in sorted(self.keys_kco):
                    freport.write(key + ' : ' + str(self.keys_kco[key]) + '\n')
                freport.write("\nSecurity options:\n")
                for key in sorted(self.security_kco):
                    freport.write(key + ' : ' + str(self.security_kco[key]) + '\n')
                freport.write("\nIntegrity options:\n")
                for key in sorted(self.integrity_kco):
                    freport.write(key + ' : ' + str(self.integrity_kco[key]) + '\n')
          with open(self.reportdir + problemsreport + imagebasename, 'w') as freport:
                freport.write("Report for image: " + imagebasename + '\n')
                freport.write("With the kernel conf at: " + kernel_conf + '\n\n')
                freport.write("Hardening options that need improvement:\n")
                for key in sorted(self.hardening_kco):
                    if (self.hardening_kco[key] != self.hardening_kco_ref[key]) :
                        freport.write("\nActual value:\n")
                        freport.write(key + ' : ' + str(self.hardening_kco[key]) + '\n')
                        freport.write("Recommended value:\n")
                        freport.write(key + ' : ' + str(self.hardening_kco_ref[key]) + '\n')
                freport.write("\nKey-related options that need improvement:\n")
                for key in sorted(self.keys_kco):
                    if (self.keys_kco[key] != self.keys_kco_ref[key]) :
                        freport.write("\nActual value:\n")
                        freport.write(key + ' : ' + str(self.keys_kco[key]) + '\n')
                        freport.write("Recommended value:\n")
                        freport.write(key + ' : ' + str(self.keys_kco_ref[key]) + '\n')
                freport.write("\nSecurity options that need improvement:\n")
                for key in sorted(self.security_kco):
                    if (self.security_kco[key] != self.security_kco_ref[key]) :
                        valid = False
                        if (key == "CONFIG_DEFAULT_SECURITY"):
                            options = self.security_kco_ref[key].split(',')
                            print("Options: ", options)
                            for option in options:
                                if (option == self.security_kco[key]):
                                    valid = True
                                    break
                        if ((key == "CONFIG_SECURITY_SELINUX") or 
                           (key == "CONFIG_SECURITY_SMACK") or
                           (key == "CONFIG_SECURITY_APPARMOR") or
                           (key == "CONFIG_SECURITY_TOMOYO")) :
                            if ((self.security_kco['CONFIG_SECURITY_SELINUX'] == 'y') or 
                                (self.security_kco['CONFIG_SECURITY_SMACK'] == 'y') or
                                (self.security_kco['CONFIG_SECURITY_APPARMOR'] == 'y') or
                                (self.security_kco['CONFIG_SECURITY_TOMOYO'] == 'y')):
                                valid = True
                        if valid == False:
                            freport.write("\nActual value:\n")
                            freport.write(key + ' : ' + str(self.security_kco[key]) + '\n')
                            freport.write("Recommended value:\n")
                            freport.write(key + ' : ' + str(self.security_kco_ref[key]) + '\n')
                freport.write("\nIntegrity options that need improvement:\n")
                for key in sorted(self.integrity_kco):
                    if (self.integrity_kco[key] != self.integrity_kco_ref[key]) :
                        freport.write("\nActual value:\n")
                        freport.write(key + ' : ' + str(self.integrity_kco[key]) + '\n')
                        freport.write("Recommended value:\n")
                        freport.write(key + ' : ' + str(self.integrity_kco_ref[key]) + '\n')
        else:
            print("Plugin hasn't initialized! Not performing the call.")

#======== supported callbacks from ISA =============#

def init(proxy, reportdir):
    global KCAnalyzer 
    KCAnalyzer = ISA_KCA(proxy, reportdir)
def getPluginName():
    return "kenel_config_check"
def process_kernel_conf(kernel_conf, imagebasename):
    global KCAnalyzer 
    return KCAnalyzer.process_kernel_conf(kernel_conf, imagebasename)

#====================================================#

