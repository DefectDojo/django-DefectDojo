---
title: "Product Health Grading"
description: "Products are graded based on their health."
draft: false
weight: 2
---

## Product Health Grading

Within DefectDojo's system settings, you have the opportunity to enable a grading system for your products. For that you have to enable ("Enable Product Grading"). Then, the products are graded with the following possible grades:
- Grade A
- Grade B
- Grade C
- Grade D
- Grade F

The best grade is A going down to the worst grade F. By default the grades stick to the achieved percentage mentioned in grade converation [here](https://en.wikipedia.org/wiki/Academic_grading_in_the_United_States). 

### Calculation of the grades
The code that performs the grade calculations can be found [here](https://github.com/DefectDojo/django-DefectDojo/blob/76e11c21e88fb84b67b6da27c78fbbe1899e7e78/dojo/management/commands/system_settings.py#L8).

The highest health score is 100 and it decreases based on the number of findings for each severity (critical, high, medium, low) within the product. In the following code snippet you can see the rules. 
Note that the following abbreviations were used:

- crit: amount of critical findings within the product
- high: amount of high findings within the product
- med: amount of medium findings within the product
- low: amount of low findings within the product

```
health=100
if crit > 0:
    health = 40
    health = health - ((crit - 1) * 5)
if high > 0:
    if health == 100:
        health = 60
    health = health - ((high - 1) * 3)
if med > 0:
    if health == 100:
        health = 80
    health = health - ((med - 1) * 2)
if low > 0:
    if health == 100:
        health = 95
    health = health - low
if health < 5:
    health = 5
return health
```