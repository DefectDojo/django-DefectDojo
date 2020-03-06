from tagging.managers import TagDescriptor


class PrefetchingTagDescriptor(object):

    def get_with_prefetch(self, instance, owner):
        if instance:
            # print('returning prefetched tags')
            return [ti.tag for ti in list(instance.tagged_items.all())]

        return self.__old__get__(instance, owner)

    def patch():
        print('patching TagDescriptor')
        TagDescriptor.__old__get__ = TagDescriptor.__get__
        TagDescriptor.__get__ = PrefetchingTagDescriptor.get_with_prefetch

    def unpatch():
        # can be used in unit tests to compare old and new behaviour
        print('unpatching TagDescriptor')
        TagDescriptor.__get__ = TagDescriptor.__old__get__
