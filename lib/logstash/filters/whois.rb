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
  # Values are matched with prefixes respectively. In the 
  # example below, the filter would lookup the domain in a
  # field named 'domain_or_ip01' and then create fields like
  # 'domain_or_ip01_created_epoch', etc.
  #
  # The config should look like this:
  # [source,ruby]
  #     filter {
  #       whois {
  #         lookup_fields => [ "domain_or_ip01", "ip_or_domain02" ]
  #       }
  #     }
  config_name "whois"
  
  # Verify that our config values are an array
  config :lookup_fields, :validate => :array

  # Replace the message with this value.
  config :message, :validate => :string, :default => "Hello World!"
  

  public
  def register
    require "whois"
    require "timeout"
    # Add instance variables 
  end # def register

  public
  def filter(event)


    if @lookup_fields


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

            create_field_epoch = field + "_whois_created_epoch"
            create_field_string = field + "_whois_created_string"
            event[create_field_epoch] = d.getTime/1000
            event[create_field_string] = d.toString

            update_field_epoch = field + "_whois_updated_epoch"
            update_field_string = field + "_whois_updated_string"
            event[update_field_epoch] = e.getTime/1000
            event[update_field_string] = e.toString

            expire_field_epoch = field + "_whois_expires_epoch"
            expire_field_string = field + "_whois_expires_string"
            event[expire_field_epoch] = f.getTime/1000
            event[expire_field_string] = f.toString

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
