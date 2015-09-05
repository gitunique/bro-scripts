#
# Script used to provide data to the statsd plugin
#
# See https://github.com/JustinAzoff/bro-statsd-plugin
#
# Works with https://github.com/kamon-io/docker-grafana-graphite
#

@load base/protocols/http
@load base/protocols/ssh
@load-plugin NCSA::Statsd

event connection_established(c: connection)
{
	statsd_increment("bro.connection.established", 1);
}

event connection_rejected(c: connection)
{
	statsd_increment("bro.connection.rejected", 1);
}

event HTTP::log_http(rec: HTTP::Info)
{
	local size = rec$response_body_len;

	statsd_increment("bro.http.request", 1);
	statsd_increment("bro.http.bytes", size);

	local s = fmt("bro.http.status_code.%d", rec$status_code);
	statsd_increment(s, 1);
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
	if ( c$dns$qtype_name=="A")
	{
		statsd_increment("bro.dns.query_type.a", 1);
		if ( msg$rcode==3 ) #rcode=3 for NXDOMAIN
		{
			statsd_increment("bro.dns.nxdomain", 1);
		}
	}

	else
	{
		local s = fmt("bro.dns.query_type.%s", c$dns$qtype_name);
		statsd_increment(s, 1);
	}

}

event ssh_auth_successful(c: connection, auth_method_none: bool)
{
       if (c$id$resp_h == 192.168.1.77 && c$id$orig_h !in 192.168.1.0/24)
                {
			statsd_increment("bro.ssh.login.remote-to-local", 1);
		}
        if (c$id$resp_h in 192.168.1.0/24 && c$id$orig_h in 192.168.1.0/24)
                {
			statsd_increment("bro.ssh.login.local-to-local", 1);
		}
        else
		{
			statsd_increment("bro.ssh.login.local-to-remote", 1);
		}
}

event ssh_auth_failed(c: connection)
{
       if (c$id$resp_h == 192.168.1.77 && c$id$orig_h !in 192.168.1.0/24)
                {
			statsd_increment("bro.ssh.login.failed.remote-to-local", 1);
		}
        if (c$id$resp_h in 192.168.1.0/24 && c$id$orig_h in 192.168.1.0/24)
                {
			statsd_increment("bro.ssh.login.failed.local-to-local", 1);
		}
        else
		{
			statsd_increment("bro.ssh.login.failed.local-to-remote", 1);
		}

}
