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
# Hat tip to https://github.com/hosom/bro-file-extraction
#

# needed to keep bro running while waiting for when to complete
redef exit_only_after_terminate=T;

# add cuckoo_id column to files.log file
redef record Files::Info += {
    cuckoo_id: int &optional &log;
};

global my_ext_map: table[string] of string = {
    ["application/msword"] = "doc",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
    ["application/java-archive"] = "jar",
    ["application/x-java-applet"] = "jar",
    ["application/x-java-jnlp-file"] = "jnlp",
    ["application/x-dosexec"] = "exe",
    ["application/pdf"] = "pdf",
    ["application/zip"] = "zip",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
} &default ="";

const extraction_types: set[string] = { 
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/x-dosexec",
    "application/pdf",
    "application/zip",
    "application/java-archive",
    "application/x-java-applet",
    "application/x-java-jnlp-file"
};

export
{
    const tool = fmt("/usr/local/bin/cuckoo-submit.sh");
    redef enum Notice::Type += {
        ## Generated if file is extracted and analysed
        File::Cuckoo_Submission
    };
}

function submit_cuckoo(f: fa_file): int
{
        local command = Exec::Command($cmd=fmt("%s extract_files/%s",tool,f$info$extracted));
        return when ( local result = Exec::run(command)){
            local id: int  = to_int(result$stdout[0]);
            return id;
        }
}


event file_sniff(f: fa_file, meta: fa_metadata)
{
    if ( meta?$mime_type && meta$mime_type in extraction_types )
    { 
    local ext = "";
        ext = my_ext_map[meta$mime_type];
        local fname = fmt("%s-%s.%s", f$source, f$id, ext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]); 
     }
}

event file_state_remove( f: fa_file )
{
    if (f$info?$extracted) {
        when (local id = submit_cuckoo(f)){
            f$info$cuckoo_id = id;
            print fmt("Cuckoo ID value set: %d", f$info$cuckoo_id);
            NOTICE([$note=File::Cuckoo_Submission,$msg=fmt("https://cuckoo/analysis/%s", id),$f=f]);
        }
    }
}

