# Insert this into security/Kconfig to build as part of the kernel
#   (you don't need this if you're just building a module)

config SECURITY_CAP_OVER
	tristate "Capability Override LSM (EXPERIMENTAL)"
	depends on SECURITY!=n
	help
	  This enables a process to (automatically) gain one or more POSIX.1e
          capabilities based on it's uid/gid/path, the settings for which can
          be configured via sysctl or /proc

          This module seems to work well, and might be useful for you. However,
          at this time it has not been audited or checked over by any kernel
          hackers, so don't use it in any production systems without careful
          testing.

	  If you are unsure how to answer this question, answer N.
