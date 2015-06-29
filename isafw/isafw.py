# main class of Image Security Analyser
import os
import sys
import imp
import isaplugins


__all__ = [
    'ISA_package',
    'ImageSecurityAnalyser',
    ]

# class for representing a package for ISA plugins

class ISA_package:
    name = ""                     # pkg name (mandatory argument)
    version = ""                  # full version
    licenses = []                 # list of licences for all subpackages
    source_files = []             # list of strings of source files (tarball, patches, spec)
    patch_files = []              # list of patch files to be applied
    path_to_sources = ""          # path to the source files (mandatory argument)
    path_to_spec = ""             # path to the spec file

class ImageSecurityAnalyser:
    def __init__(self, proxy):
        for name in isaplugins.__all__:
            plugin = getattr(isaplugins, name)
            try:
                # see if the plugin has a 'init' attribute
                register_plugin = plugin.init
            except:
                print("Error in calling init() for plugin " + plugin.getPluginName())
                print("Error info: ", sys.exc_info())
                print("Skipping this plugin")
                continue           
            else:
                try:
                    register_plugin(proxy)
                except:
                    print("Exception in plugin init: ", sys.exc_info())

    def process_package_source(self, ISA_package, report_path):
        for name in isaplugins.__all__:
            plugin = getattr(isaplugins, name)
            try:
                # see if the plugin has a 'process_package_source' attribute
                process_package_source = plugin.process_package_source
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_package_source(ISA_package, report_path)
                except:
                    print("Exception in plugin: ", sys.exc_info())

    def process_package_list(self, package_list):
        # print package_list
        for name in isaplugins.__all__:
            plugin = getattr(isaplugins, name)
            try:
                # see if the plugin has a 'process_package_list' attribute
                process_package_list = plugin.process_package_list
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_package_list(package_list)
                except:
                    print("Exception in plugin: ", sys.exc_info())

    def process_fsroot(self, fsroot_path, imagebasename, report_path):
        # print fsroot_path
        for name in isaplugins.__all__:
            plugin = getattr(isaplugins, name)
            try:
                # see if the plugin has a 'process_fsroot' attribute
                process_fsroot = plugin.process_fsroot
            except AttributeError:
                # if it doesn't, it is ok, won't call this plugin
                pass
            else:
                try:
                    process_fsroot(fsroot_path, imagebasename, report_path)
                except:
                    print("Exception in plugin: ", sys.exc_info())




