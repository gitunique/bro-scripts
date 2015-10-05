#
# This script will undertale additional processing of files extracted
# by the ANALYZER_EXTRACT module.
#
# Requires that the global ext_map contained in the
# bro/share/bro/file-extraction/extract.bro
# file includes relevant mime_types
#
# The cuckoo-submit.sh script will take an action on the extracted file:
# - submitting it to cuckoo sandbox or other automated analysis platform
#

export {
    const tool = fmt("/usr/local/bin/cuckoo-submit.sh");
}

function submit_cuckoo(f: string)
    {
    local command = Exec::Command($cmd=fmt("%s %s",tool,f));

    when ( local result = Exec::run(command) )
   	    {
   	    print fmt("Cuckoo submission script complete");
   	    }
    }

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta$mime_type == "application/x-dosexec" || meta$mime_type == "application/zip" || meta$mime_type == "application/pdf" )
        {
        local ext = "";

        if ( meta?$mime_type )
            ext = ext_map[meta$mime_type];

  	    local fname = fmt("/nsm/bro/extracted/%s-%s.%s", f$source, f$id, ext);

        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
        }
    }

event file_state_remove( f: fa_file )
    {
    if ( f$info?$extracted )
        submit_cuckoo(f$info$extracted);
    }
