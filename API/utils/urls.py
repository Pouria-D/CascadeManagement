from collections import OrderedDict

from rest_framework.reverse import reverse_lazy


def sub_router(router, request):
    url_names = list()
    for item in router.urls:
        if '-list' in item.name and '/' not in str(item.pattern):
            url_names.append({
                "pattern": str(item.pattern)[1:-1],
                "name": item.name
            })

    api_sub_root = OrderedDict()
    for item in url_names:
        api_sub_root[item['pattern']] = reverse_lazy(item['name'], request=request)

    return api_sub_root
