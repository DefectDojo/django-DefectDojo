from django.contrib.contenttypes.models import ContentType
from tagging.models import Tag
from tagging.managers import TagDescriptor, ModelTagManager
from django.db.models import F
from collections import defaultdict
from django.db import connection

class PrefetchingTagDescriptor(object):
    
    def get_with_prefetch(self, instance, owner):
        print('self:', self)
        print('instance:', instance.id)
        print('owner:', owner)
        # print('what:', what)

        # print('type(self):', type(self))
        
        if instance:
            # use getattr to avoid 'implicit booleaness of empty lists'
            if getattr(instance, 'prefetched_tags', None) is not None:
                print('returning prefetched tags')
                return instance.prefetched_tags
                
        return self.__old__get__(instance, owner)

    def patch():
        print('patching TagDescriptor')
        TagDescriptor.__old__get__ = TagDescriptor.__get__
        TagDescriptor.__get__ = PrefetchingTagDescriptor.get_with_prefetch


    def prefetch_tags(objs):
    
        print('constructing list of ids')
        id_list = []
        for obj in objs:
            id_list.append(obj.id)
        
        if len(id_list) == 0:
            return objs
        
        # print(id_list)


        print('getting content type')
        ctype = ContentType.objects.get_for_model(objs[0])
        # print(ctype.id)

        start = len(connection.queries)

        print('initial query for all tags')
        tags = Tag.objects.filter(items__content_type__pk=ctype.pk,
                           items__object_id__in=id_list).annotate(obj_id=F('items__object_id')).values('obj_id', 'name').order_by('obj_id')
        # tags = list(tags)
        # print(tags)

        # for i in range(start, len(connection.queries)):
        #     print(connection.queries[i])

        print('constructing the dict')
        d = defaultdict(list)
        for item in tags:
            d[item['obj_id']].append(item['name'])
            # print(d.items())
            # print(d[368])

        print(d)

        print('assigning entries to prefetched_tags')
        for obj in objs:
            # delattr(obj, 'tags')
            print('setting tags_cache for: ' + str(obj.id) + ' to: ' + str(d.get(obj.id, [])))
            obj.prefetched_tags = d.get(obj.id, [])

            # print('printing tags for: ', obj.id)
            # print(obj.prefetched_tags)
            # for i in range(start, len(connection.queries)):
            #     print(connection.queries[i])

        return objs
        # output = [dict(zip(['id', 'tags'], item)) for item in d.items()]
        # print(output)
        # return output
