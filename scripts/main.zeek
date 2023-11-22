module corelight_version;
@load base/frameworks/reporter
@load base/utils/strings.zeek

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Number representing the version which can be used for easy comparison.
		## The format of the number is ABBCC with A being the major version,
		## bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
		## As an example, Zeek 2.4.1 results in the number 20401.
		version_number: count &log &optional;
	};
}
event zeek_init()
	{
	Log::create_stream(corelight_version::LOG, [ $columns=corelight_version::Info,
	    $path="zeek_version" ]);
	}

event connection_established(c: connection)
	{
	local log: Info = [ $version_number=Version::info$version_number ];
	Log::write(corelight_version::LOG, log);
	}
