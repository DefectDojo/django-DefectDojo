import hyperlink
from django.core.exceptions import ValidationError


def from_uri():

    try:
        url = hyperlink.parse(url='strange.prod.dev\n123.45.6.30', decoded=False)
    except Exception as e:
        raise ValidationError('Invalid URL format: {}'.format(e))

    query_parts = []  # inspired by
    # https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py
    # #L1768
    for k, v in url.query:
        if v is None:
            query_parts.append(k)
        else:
            query_parts.append(u"=".join([k, v]))
    query_string = u"&".join(query_parts)

    # return Endpoint(
    #     protocol=url.scheme if url.scheme != '' else None,
    #     userinfo=':'.join(url.userinfo) if url.userinfo not in [(), ('',)] else None,
    #     host=url.host if url.host != '' else None,
    #     port=url.port,
    #     path='/'.join(url.path)[:500] if url.path not in [None, (), ('',)] else None,
    #     query=query_string[:1000] if query_string is not None and query_string != '' else None,
    #     fragment=url.fragment[:500] if url.fragment is not None and url.fragment != '' else None
    # )


booger = from_uri()
