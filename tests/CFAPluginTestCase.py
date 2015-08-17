#
# CFAPluginTestCase.py -  Test cases for CFA plugin, part of ISA FW
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
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE

import unittest
import sys
sys.path.append("../isafw") 
import isafw
import shutil
import os
import filecmp
import tarfile

reportdir = "./cfa_plugin/output"
fsroot_tar = "./cfa_plugin/data/rootfs.tar.gz"
fsroot_path = "./cfa_plugin/data/rootfs"
ref_cfa_full_output = "./cfa_plugin/data/ref_cfa_full_report_TestImage"
ref_cfa_problems_output = "./cfa_plugin/data/ref_cfa_problems_report_TestImage"

class TestCFAPlugin(unittest.TestCase):

    def setUp(self):
        # cleaning up the report dir and creating it if needed
        if os.path.exists(os.path.dirname(reportdir+"/internal/test")):
            shutil.rmtree(reportdir)
        os.makedirs(os.path.dirname(reportdir+"/internal/test"))
        # fetching proxy info
        proxy = ""
        if "http_proxy" in os.environ:
            proxy = os.environ['http_proxy']
        if "https_proxy" in os.environ:
            proxy = os.environ['https_proxy']
        # unpacking rootfs
        fsroot_arch = tarfile.open(name=fsroot_tar, mode='r')
        fsroot_arch.extractall(path=fsroot_path, members=None)
        # creating ISA FW class
        self.imageSecurityAnalyser = isafw.ISA(proxy, reportdir)
        fs = isafw.ISA_filesystem()
        fs.img_name = "TestImage"
        fs.path_to_fs = fsroot_path
        self.imageSecurityAnalyser.process_filesystem(fs)

    def tearDown(self):
        if os.path.exists(os.path.dirname(fsroot_path +"/test")):
            shutil.rmtree(fsroot_path)
        os.makedirs(os.path.dirname(fsroot_path+"/test"))

    def test_cfa_full_report(self):
        self.assertTrue(filecmp.cmp(reportdir + "/cfa_full_report_TestImage", ref_cfa_full_output),
                         'Output does not match')

    def test_cfa_problems_report(self):
        self.assertTrue(filecmp.cmp(reportdir + "/cfa_problems_report_TestImage", ref_cfa_problems_output),
                         'Output does not match')

 
if __name__ == '__main__':
    unittest.main()
