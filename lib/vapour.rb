require 'openssl'
require 'cgi'
require 'time'
require 'base64'
require 'net/http'
require 'json'
require 'pp'

require 'nokogiri'

class Vapour
  Error = Class.new(RuntimeError)
  ValidationError = Class.new(Error)

  def initialize(key, secret)
    @aws_key = key
    @aws_secret = secret
    @url = URI('https://cloudformation.eu-west-1.amazonaws.com/')
  end

  def describe_stacks(name = nil)
    if name
      request('Action' => 'DescribeStacks', 'StackName' => name)
    else
      request('Action' => 'DescribeStacks')
    end
  end

  # options are:
  #   LogicalResourceId
  #   PhysicalResourceId
  #   StackName
  def describe_stack_resources(query = {})
    pass = {'Action' => 'DescribeStackResources'}.merge(query)
    request(pass)
  end

  # Validates a specified template.
  # String containing the template body. (For more information, go to the AWS CloudFormation User Guide.)
  # TemplateBody
  def validate_template_body(body)
    request('Action' => 'ValidateTemplate',
            'TemplateBody' => body)
  end

  # Validates a specified template.
  # TemplateURL
  def validate_template_url(url)
    request('Action' => 'ValidateTemplate',
            'TemplateURL' => url)
  end

  def request(query)
    url, data = prepare_url(query)

    request = Net::HTTP::Post.new(url.path)
    request['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'
    request.body = sign_request('POST', url, data)
    response = Net::HTTP.start(url.host, url.port, :use_ssl => true){|http| http.request(request) }

    case response
    when Net::HTTPSuccess
      handle_success(response)
    else
      handle_error(response)
    end
  end

  def prepare_url(query)
    url = @url.dup
    data = {
      'Version' => '2010-05-15',
      'SignatureVersion' => 2,
      'AWSAccessKeyId' => @aws_key,
    }.merge(query)

    return url, data
  end

  NS = {'aws' => 'http://cloudformation.amazonaws.com/doc/2010-05-15/'}

  def handle_success(response)
    Nokogiri::XML(response.body)
  end

  def handle_error(response)
    xml = Nokogiri::XML(response.body)
    error = xml.xpath('//aws:ErrorResponse', NS)
    type = error.xpath('//aws:Type', NS).text
    code = error.xpath('//aws:Code', NS).text
    message = error.xpath('//aws:Message', NS).text
    raise "Type: #{type}, Code: #{code}, Message: #{message}"
  end

  DIGEST = OpenSSL::Digest::Digest.new("sha256")

  def sign_request(verb, url, data)
    data['Timestamp'] ||= Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z') unless data["Expires"]
    data["SignatureVersion"] = 2
    data['SignatureMethod'] = 'HmacSHA256'

    query_string = data.sort_by{|key, value| key }.map{|key, value|
      [escape(key), escape(value)].join('=')
    }.join('&')

    string = [verb.to_s.upcase, url.host.downcase, url.path, query_string].join("\n")
    hmac = OpenSSL::HMAC.digest(DIGEST, @aws_secret, string)
    signature = CGI.escape(Base64.encode64(hmac).strip)
    "#{query_string}&Signature=#{signature}"
  end

  def escape(query_param)
    CGI.escape(query_param.to_s).
      gsub("%7E", "~").
      gsub("+", "%20").
      gsub("*", "%2A")
  end
end

key = ENV['AWS_ACCESS_KEY_ID']
secret = ENV['AWS_SECRET_ACCESS_KEY']
vapour = Vapour.new(key, secret)
puts vapour.describe_stacks
puts vapour.describe_stack_resources('StackName' => 'sns2')
