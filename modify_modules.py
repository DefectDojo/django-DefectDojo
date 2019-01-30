import sys
import imp 
import threading 
import fileinput
import os

path = (imp.find_module('django')[1])[:-6]


def modify_models(path_name):
    replacements = [
                    '    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)',
                    '    field = models.ForeignKey(CustomField, related_name=\'instance\', on_delete=models.CASCADE)',
                    '    content_type = models.ForeignKey(ContentType, blank=True, null=True, on_delete=models.CASCADE)'
                    ]
    replaced = 0
    directory = path_name[:-10]
    new_file = open( (directory + '/models_n.py'),'w')
    with open(path_name) as old_file:
        for line in old_file:
            if 'models.ForeignKey' in line:
                new_file.write(replacements[replaced] + '\n')
                replaced += 1
            else:
                new_file.write(line)
    
    old_file.close()
    new_file.close()
    
    os.remove(directory + '/models.py')
    os.rename(directory + '/models_n.py', directory + '/models.py')

    return
    
def modify_initial(path_name):
    replacements = [
                    '\t\t\t\t(\'content_type\', models.ForeignKey(to=\'contenttypes.ContentType\', on_delete=models.CASCADE)),',
                    '\t\t\t\t(\'content_type\', models.ForeignKey(blank=True, to=\'contenttypes.ContentType\', null=True, on_delete=models.CASCADE)),',
                    '\t\t\t\t(\'field\', models.ForeignKey(related_name=\'instance\', to=\'custom_field.CustomField\', on_delete=models.CASCADE)),'
                    ]
    replaced = 0
    directory = path_name[:-16]
    new_file = open( (directory + '/0001_initial_n.py'),'w')
    with open(path_name) as old_file:
        for line in old_file:
            if 'models.ForeignKey' in line:
                new_file.write(replacements[replaced] + '\n')
                replaced += 1
            else:
                new_file.write(line)
    
    old_file.close()
    new_file.close()

    os.remove(directory + '/0001_initial.py')
    os.rename(directory + '/0001_initial_n.py', directory + '/0001_initial.py')
    
    return        
    

def modify_views(path_name):
    replacements = [
                    'from django.urls import reverse'
                    ]
    replaced = 0
    directory = path_name[:-9]
    new_file = open( (directory + '/views_n.py'),'w')
    with open(path_name) as old_file:
        for line in old_file:
            if 'django.core.urlresolvers' in line:
                new_file.write(replacements[replaced] + '\n')
                replaced += 1
            else:
                new_file.write(line)
    
    old_file.close()
    new_file.close()
    
    os.remove(directory + '/views.py')
    os.rename(directory + '/views_n.py', directory + '/views.py')

    return


def modify_mapping(path_name):
    replacements = [
                    'QUERY_TERMS = {',
                    '\t  \'exact\', \'iexact\', \'contains\', \'icontains\', \'gt\', \'gte\', \'lt\', \'lte\', \'in\',',
                    '\t  \'startswith\', \'istartswith\', \'endswith\', \'iendswith\', \'range\', \'year\',',
                    '\t  \'month\', \'day\', \'week_day\', \'hour\', \'minute\', \'second\', \'isnull\', \'search\',',
                    '\t  \'regex\', \'iregex\',',
                    '\t  }'
                    ]
    replaced = 0
    directory = path_name[:-11]
    new_file = open( (directory + '/mapping_n.py'),'w')
    with open(path_name) as old_file:
        for line in old_file:
            if 'import QUERY_TERMS' in line:
                while replaced < len(replacements):
                    new_file.write(replacements[replaced] + '\n')
                    replaced += 1
            else:
                new_file.write(line)
    
    old_file.close()
    new_file.close()
    
    os.remove(directory + '/mapping.py')
    os.rename(directory + '/mapping_n.py', directory + '/mapping.py')

    return

def run_conversion():
    t1 = threading.Thread(target=modify_models, args=((path + 'custom_field/models.py'), ))
    t2 = threading.Thread(target=modify_initial, args=((path + 'custom_field/migrations/0001_initial.py'), ))
    t3 = threading.Thread(target=modify_views, args=((path + 'tastypie_swagger/views.py'), ))
    t4 = threading.Thread(target=modify_mapping, args=((path + 'tastypie_swagger/mapping.py'), ))
    
    t4.start()
    t3.start()
    t1.start()
    t2.start()
    
    t2.join()
    t1.join()
    t3.join()
    t4.join()