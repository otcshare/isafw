# Security scanning class
#
# Based in part on buildhistory.bbclass which was in turn based on
# testlab.bbclass and packagehistory.bbclass
#
# Copyright (C) 2011-2015 Intel Corporation
# Copyright (C) 2007-2011 Koen Kooi <koen@openembedded.org>
#

LICENSE = "MIT"

ISAFW_WORKDIR = "${WORKDIR}/isafw"
ISAFW_REPORTDIR ?= "${LOG_DIR}/isafw-report"

do_analyse_sources[depends] += "cve-check-tool-native:do_populate_sysroot"
do_analyse_sources[depends] += "rpm-native:do_populate_sysroot"
do_analyse_sources[nostamp] = "1"

# First, code to handle scanning each recipe that goes into the build

do_analyse_sources[cleandirs] = "${ISAFW_WORKDIR}"

python do_analyse_sources() {

    from isafw import *
    
    proxy = d.getVar('HTTP_PROXY', True)
    if not proxy :
        proxy = d.getVar('http_proxy', True)
    bb.debug(1, 'isafw: proxy is %s' % proxy)

    reportdir = d.getVar('ISAFW_REPORTDIR', True)
    if not os.path.exists(os.path.dirname(reportdir+"/internal/test")):
        os.makedirs(os.path.dirname(reportdir+"/internal/test"))

    imageSecurityAnalyser = isafw.ISA(proxy, reportdir)

    if not d.getVar('SRC_URI', True):
        # Recipe didn't fetch any sources, nothing to do here I assume?
        return

    # Unpack the sources again, because we need the pristine sources
    # (we could do this after do_unpack instead and save some time, but that
    # would necessitate having a way of restoring the results of the scan
    # from sstate as well)

    fetch = bb.fetch2.Fetch([], d)
    for url in fetch.urls:
        workdir = d.getVar('ISAFW_WORKDIR', True)
        fetch.unpack(workdir, (url,))

    recipe = isafw.ISA_package()
    recipe.name = d.getVar('PN', True)
    recipe.version = d.getVar('PV', True)
    licenses = d.getVar('LICENSE', True)
    licenses = licenses.replace("(", "")
    licenses = licenses.replace(")", "")
    recipe.licenses = licenses.split()
    while '|' in recipe.licenses:
        recipe.licenses.remove('|')
    while '&' in recipe.licenses:
        recipe.licenses.remove('&')
    # translate to proper format
    spdlicense = []
    for l in recipe.licenses:
        spdlicense.append(canonical_license(d, l))
    recipe.licenses = spdlicense
    recipe.path_to_sources = workdir
    
    for patch in src_patches(d):
        _,_,local,_,_,_=bb.fetch.decodeurl(patch)
        recipe.patch_files.append(os.path.basename(local))
    if (not recipe.patch_files) :
        recipe.patch_files.append("None")
    # Pass the recipe object to the security framework

    bb.debug(1, '%s: analyse sources in %s' % (d.getVar('PN', True), workdir))
    imageSecurityAnalyser.process_package(recipe)

    # If we're unpacking our own sources we might want to discard them at this point

    return
}

addtask do_analyse_sources after do_fetch before do_build

addtask analyse_sources_all after do_analyse_sources
do_analyse_sources_all[recrdeptask] = "do_analyse_sources_all do_analyse_sources"
do_analyse_sources_all[recrdeptask] = "do_${BB_DEFAULT_TASK}"
do_analyse_sources_all() {
	:
}

python() {
    # We probably don't need to scan native/cross
    if bb.data.inherits_class('native', d) or bb.data.inherits_class('cross', d):
        bb.build.deltask('do_analyse_sources', d)
}

python analyse_image() {

    # Directory where the image's entire contents can be examined
    rootfsdir = d.getVar('IMAGE_ROOTFS', True)

    imagebasename = d.getVar('IMAGE_BASENAME', True)
    reportdir = d.getVar('ISAFW_REPORTDIR', True)

    proxy = d.getVar('HTTP_PROXY', True)
    if not proxy :
        proxy = d.getVar('http_proxy', True)

    bb.debug(1, 'isafw: proxy is %s' % proxy)

    from isafw import *
    imageSecurityAnalyser = isafw.ISA(proxy, reportdir)

    pkglist = manifest2pkglist(d)

    kernelconf = d.getVar('STAGING_KERNEL_BUILDDIR', True) + "/.config"

    kernel = isafw.ISA_kernel()
    kernel.img_name = imagebasename
    kernel.path_to_config = kernelconf

    bb.debug(1, 'do kernel conf analysis on %s' % kernelconf)
    imageSecurityAnalyser.process_kernel(kernel)

    pkg_list = isafw.ISA_pkg_list()
    pkg_list.img_name = imagebasename
    pkg_list.path_to_list = pkglist

    bb.debug(1, 'do pkg list analysis on %s' % pkglist)
    imageSecurityAnalyser.process_pkg_list(pkg_list)

    fs = isafw.ISA_filesystem()
    fs.img_name = imagebasename
    fs.path_to_fs = rootfsdir

    bb.debug(1, 'do image analysis on %s' % rootfsdir)
    imageSecurityAnalyser.process_filesystem(fs)
}

do_rootfs[depends] += "checksec-native:do_populate_sysroot"

# Ensure we wait until source analysis gets done for all recipes whose packages
# are going into the image before starting with the image itself
do_rootfs[recrdeptask] += "do_analyse_sources"

analyse_image[fakeroot] = "1"

def manifest2pkglist(d):

    manifest_file = d.getVar('IMAGE_MANIFEST', True)
    imagebasename = d.getVar('IMAGE_BASENAME', True)
    reportdir = d.getVar('ISAFW_REPORTDIR', True)

    pkglist = reportdir + "/internal/pkglist_" + imagebasename

    with open(pkglist, 'w') as foutput:
        with open(manifest_file, 'r') as finput:
            for line in finput:
                items = line.split()
                foutput.write(items[0] + " " + items[2] + "\n")

    return pkglist


IMAGE_POSTPROCESS_COMMAND += " analyse_image ; "

# NOTE: by the time IMAGE_POSTPROCESS_COMMAND items are called, the image
# has been stripped of the package manager database (if runtime package management
# is not enabled, i.e. 'package-management' is not in IMAGE_FEATURES). If you
# do want to be using the package manager to operate on the image contents, you'll
# need to call your function from ROOTFS_POSTINSTALL_COMMAND or
# ROOTFS_POSTUNINSTALL_COMMAND instead - however if you do that you should then be
# aware that what you'll be looking at isn't exactly what you will see in the image
# at runtime (there will be other postprocessing functions called after yours).

# this will be run once per build in order to initialize and cleanup report dir
python isafwreport_handler () {

    import shutil

    reportdir = e.data.getVar('ISAFW_REPORTDIR', True)
    if os.path.exists(os.path.dirname(reportdir+"/internal/test")):
        shutil.rmtree(reportdir)
    os.makedirs(os.path.dirname(reportdir+"/internal/test"))

}
addhandler isafwreport_handler
isafwreport_handler[eventmask] = "bb.event.BuildStarted"

