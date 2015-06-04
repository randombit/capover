Capability Override LSM, v0.9.3
October 10, 2004
http://www.randombit.net/projects/cap_over/

The Capability Override LSM is a Linux Security Module which allows you to tell
the kernel to give a particular process one or more POSIX.1e capabilities,
based on the processes uid, gid, and/or executable pathname. This allows you to
specify fairly complicated policies, for example giving a particular program a
single capability, but only when executed by a particular user.

Other files you may want to examine include:
  doc/log.txt       - What's new in this version
  doc/policy.txt    - How to write a site policy

The current release has been tested on Linux 2.6.8 on x86. It should be
portable to all other (sane) architectures, but will not work on some older 2.6
kernels due to a recent change in a few sysctl and LSM interfaces.

Let me know if you have any problems, questions, comments, etc.

Jack Lloyd (lloyd@randombit.net)
