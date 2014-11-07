# http://tools.ietf.org/html/rfc5652#section-6.1
# http://in2eps.com/fo-cms/tk-fo-cms-ex04.html#enc1

class EncryptedData

  def initialize(algorithm_oid, algorithm_params, unprotected_attrs)
    @algorithm_oid, @algorithm_params, @unprotected_attrs = algorithm_oid, algorithm_params, unprotected_attrs
  end

  class ObjectIdentifier
    attr_reader :asn1, :dot, :label

    def initialize(asn1, short_name)
      @asn1 = asn1
      @dot = id.scan(/((?<![\d._-])\d+(?![\d._-]))/).join('.')
      @short_name = short_name
    end
  end

end
