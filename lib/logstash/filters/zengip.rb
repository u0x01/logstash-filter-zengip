# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'zeng_ip'

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::ZengIP < LogStash::Filters::Base
  config_name "zengip"

  # The path to the ZengIP database file which Logstash should use. Only City database is supported by now.
  config :database, :validate => :path

  # The field containing the IP address or hostname to map via zengip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of zengip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all geoip fields
  # are included in the event.
  #
  # For the ZengIP City database, the following are available:
  # `continent`, `country`, `province`, `city`, `district`,
  # `isp`, `dma_code`, `country_en`, `country_code`, `longitude`, and `latitude`.
  config :fields, :validate => :array, :default => %w(continent country country_en country_code province city district isp dma_code longitude latitude)

  config :target, :validate => :string, :default => 'ipinfo'

  public
  def register
    if @database.nil? || !File.exists?(@database)
      raise "You must specify 'database => ...' in your zengip filter (I looked for '#{@database}')"
    end
    @logger.info("Using zengip database", :path => @database)

    @zengip = ::ZengIP.new @database

  end # def register

  public
  def filter(event)
    ip = event.get(@source)
    ip = ip.first if ip.is_a? Array
    ipinfo = @zengip.info ip

    return tag_unsuccessful_lookup(event) if ipinfo.nil?

    event.set(@target, {}) if event.get(@target).nil?

    @fields.each do |field|
      v = ipinfo[field.to_sym]
      raise Exception.new("[#{field}] is not a supported field option.") if v.nil?
      event.set("[#{@target}][#{field}]", v.is_a?(Numeric) ? v : v.dup)
    end


      # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter


  def tag_unsuccessful_lookup(event)
    @logger.debug? && @logger.debug("IP #{event.get(@source)} was not found in the database", :event => event)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end
end # class LogStash::Filters::ZengIP
