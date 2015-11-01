#
# Scripts to analyse file metadata that may be useful in identifying suspicious activity
# Currently supports PE compile time
#
# Future versions should look at
# - office document metadata
# - PDF file attributes
#

event pe_file_header(f: fa_file, h: PE::FileHeader)
    {
    local delta_time: interval  = 30 days ;
    if ( f$pe?$compile_ts )
        {
        if ( network_time() - f$pe$compile_ts < delta_time )
            {
            NOTICE([$note=RecentCompileTime,
                    $msg=fmt("Recently compiled executable detected - file id: %s, compile time %s.",f$id,strftime("%Y-%m-%d %H:%M:%S",f$pe$compile_ts))]);
            }
        }
    }

