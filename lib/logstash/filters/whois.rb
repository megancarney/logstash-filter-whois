# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Whois < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # The filter will add fields prefixed with the value(s) you 
  # specify below. IT WILL OVERWRITE THE FIELD IF IT ALREADY
  # EXISTS.
  #
  # In the example below, the filter would lookup the domain 
  # in a field named 'domain_or_ip01' and then create fields like
  # 'domain_or_ip01_created_epoch', etc.
  #
  # An optional parameter will specify which fields you would like
  # from the whois data. By default, the plugin will add the created
  # date and the updated date.
  #
  # The full list of available fields:
  # disclaimer | String / Nil 
  # domain | String / Nil 
  # domain_id | String / Nil 
  # status | String / Nil 
  # registered? | Boolean 
  # available? | Boolean 
  # created_on | Time / Nil 
  # diff between created_on and now
  # updated_on | Time / Nil 
  # diff between updated_on and now
  # expires_on | Time / Nil 
  # diff between expires_on and now
  # registrar | Whois::Record::Registrar / Nil 
  # registrant_contacts | Array<Whois::Record::Contact> (only email)
  # admin_contacts | Array<Whois::Record::Contact> (only email)
  # technical_contacts | Array<Whois::Record::Contact> (only email)
  # nameservers | Array<Whois::Record::Nameserver> (only email)
  #
  # Example config:
  # [source,ruby]
  #     filter {
  #       whois {
  #         lookup_fields => [ "domain_or_ip01", "ip_or_domain02" ],
  #         # OPTIONAL parameter specifying that we want the created_on,
  #         # updated_on, and expires_on fields
  #         field_selection => "00000010101000000"
  #         # OPTIONAL parameter specifying which percentage of records
  #         # should be processed, default is 100%
  #         sample = "90"
  #       }
  #     }
  config_name "whois"
  
  # Verify that our config values are an array
  config :lookup_fields, :validate => :array

  # Verify the field selection string 
  # by default, choose the created_on and updated_on data
  config :field_selection, :validate => :string, :default => "00000010100000000"

  # Verify the field selection string 
  # by default, choose the created_on and updated_on data
  config :sample, :validate => :string, :default => "100"

  public
  def register
    require "whois"
    require "timeout"
    # Add instance variables 
  end # def register

  public
  def filter(event)

    if @lookup_fields

      if /^[1]{0,1}[0-9]{1,2}$/.match(@sample)
        #@logger.warn("WHOIS: I matched!")
      else
        @sample = "100"
        @logger.warn("WHOIS: sample value should be between 1 and 100 - ignoring config and using default value ", :sample => sample)
      end

      if @sample != "100"
        j = rand(100)
        @logger.warn("WHOIS: in sampling mode!", :j=>j.to_s, :sample=>sample)
        if j > @sample.to_i
          return
        end
      end

      #@logger.warn("WHOIS: field selection value is ", :field_selection => field_selection)
      # if the config string is not 17 0's or 1's, ignore
      if /^[0-1]{17}$/.match(field_selection)
        #@logger.warn("WHOIS: I matched!")
      else
        field_selection = "00000010100000000"
        @logger.warn("WHOIS: field selection value should be a 17 character string of 0's and 1's - ignoring config and using default value ", :field_selection => field_selection)
      end

      @lookup_fields.each do |field|
        is_array = false

        whois_client = Whois::Client.new
        raw = event[field]
        if raw.is_a?(Array)
          is_array = true
          if raw.length > 1
            @logger.warn("WHOIS: skipping lookup, can't deal with multiple values", :field => field, :value => raw)
          end
          raw = raw.first
        end
        unless raw.nil?
          #@logger.warn("WHOIS: I found a lookup field value! ", :field => field, :value => raw)

          retry_counter = 0
          max_tries = 10

          begin
            w = whois_client.lookup(raw)
            created_date = w.created_on
            updated_date = w.updated_on
            expired_date = w.expires_on

            # need to cast created_date
            # thanks to:
            # stackoverflow.com/questions/9032544/jruby-documentation-of-mappings-conversions-between-java-and-ruby-types-classes
            d = created_date.to_java(java.util.Date)
            e = updated_date.to_java(java.util.Date)
            f = expired_date.to_java(java.util.Date)

            if @field_selection[0] == "1"
              create_field_disclaimer = field + "_whois_disclaimer"
              event[create_field_disclaimer] = w.disclaimer
            end

            # don't know why you would use this ... but here it is
            if @field_selection[1] == "1"
              create_field_domain = field + "_whois_domain"
              event[create_field_domain] = w.domain
            end

            if @field_selection[2] == "1"
              create_field_domain_id = field + "_whois_domain_id"
              event[create_field_domain_id] = w.domain_id
            end

            if @field_selection[3] == "1"
              create_field_domain_status = field + "_whois_status"
              event[create_field_domain_status] = w.status
            end

            if @field_selection[4] == "1"
              create_field_domain_registered = field + "_whois_registered"
              event[create_field_domain_registered] = w.registered?
            end

            if @field_selection[5] == "1"
              create_field_domain_available = field + "_whois_available"
              event[create_field_domain_available] = w.available?
            end

            if @field_selection[6] == "1"
              create_field_epoch = field + "_whois_created_epoch"
              create_field_string = field + "_whois_created_string"
              event[create_field_epoch] = d.getTime/1000
              event[create_field_string] = d.toString
            end

            if @field_selection[7] == "1"
              now = java.util.Date.new
              create_field_delta = field + "_whois_created_delta"
              event[create_field_delta] = now.getTime/1000 - d.getTime/1000
            end

            if @field_selection[8] == "1"
              update_field_epoch = field + "_whois_updated_epoch"
              update_field_string = field + "_whois_updated_string"
              event[update_field_epoch] = e.getTime/1000
              event[update_field_string] = e.toString
            end

            if @field_selection[9] == "1"
              now = java.util.Date.new
              update_field_delta = field + "_whois_updated_delta"
              event[update_field_delta] = now.getTime/1000 - e.getTime/1000
            end

            if @field_selection[10] == "1"
              expire_field_epoch = field + "_whois_expires_epoch"
              expire_field_string = field + "_whois_expires_string"
              event[expire_field_epoch] = f.getTime/1000
              event[expire_field_string] = f.toString
            end

            if @field_selection[11] == "1"
              now = java.util.Date.new
              expire_field_delta = field + "_whois_expires_delta"
              event[expire_field_delta] = f.getTime/1000 - now.getTime/1000
            end

            if @field_selection[12] == "1"
              create_field_registrar_id = field + "_whois_registrar_id"
              create_field_registrar_name = field + "_whois_registrar_name"
              create_field_registrar_org = field + "_whois_registrar_org"
              create_field_registrar_url = field + "_whois_registrar_url"
              event[create_field_registrar_id] = w.registrar["id"]
              event[create_field_registrar_name] = w.registrar["name"]
              event[create_field_registrar_org] = w.registrar["organization"]
              event[create_field_registrar_url] = w.registrar["url"]
            end

            if @field_selection[13] == "1"
              create_field_registrant_ctx = field + "_whois_registrant_contact"
              event[create_field_registrant_ctx] = w.registrant_contacts[0]["email"]
            end

            if @field_selection[14] == "1"
              create_field_admin_ctx = field + "_whois_admin_contact"
              event[create_field_admin_ctx] = w.admin_contacts[0]["email"]
            end

            if @field_selection[15] == "1"
              create_field_technical_ctx = field + "_whois_technical_contact"
              event[create_field_technical_ctx] = w.technical_contacts[0]["email"]
            end

            if @field_selection[16] == "1"
              i = 0
              # how many name servers are in this record?
              num = w.nameservers.size

              while i < num  do
                create_field_nameserver = field + "_whois_nameserver" + i.to_s
                create_field_ipv4 = field + "_whois_nameserver" + i.to_s + "_ipv4"
                create_field_ipv6 = field + "_whois_nameserver" + i.to_s + "_ipv6"
                event[create_field_nameserver] = w.nameservers[i]["name"]
                event[create_field_ipv4] = w.nameservers[i]["ipv4"]
                #event[create_field_ipv4] = "oogabooga"
                event[create_field_ipv6] = w.nameservers[i]["ipv6"]
                i = i+1
              end
            end

            rescue Exception => ex
              if retry_counter < max_tries then
                @logger.warn("WHOIS: exception thrown, will try again ", :message => ex.message.to_str)
                retry_counter = retry_counter + 1
                sleep 1
                retry
              else
                @logger.warn("WHOIS: Unable to get whois information after multiple retries")
              end
          end
        end
      end

    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end
