#drop down, checkbox,radio button, waits

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.select import Select
import time

driver = webdriver.Chrome()
driver.implicitly_wait(3)
driver.get("https://demo.nopcommerce.com/register")
wait_time = WebDriverWait(driver,10)

element = wait_time.until(ec.visibility_of_element_located((By.XPATH,"//input[@placeholder='Search store']")))
element.send_keys("hai")
element = wait_time.until(ec.visibility_of_element_located((By.ID,"gender-male")))
# time.sleep(5)
print(element.is_enabled())
print(element.is_displayed())
if not element.is_selected():
    element.click()
print(element.is_selected())
element = Select(driver.find_element(By.ID,"customerCurrency"))
# element.select_by_value("https://demo.nopcommerce.com/changecurrency/6?returnUrl=%2Fregister%3FreturnUrl%3D%252F")
# element.select_by_visible_text("Euro")
# element.deselect_by_index(1)
all_optional = element.options
# element.select_by_index(1)

# for ele in element:
#     print (ele.txt)

print(len(all_optional))

for opt in all_optional:
    print(opt.text)


element = Select(driver.find_element(By.NAME,"DateOfBirthDay"))
element.select_by_value("20")
element = Select(driver.find_element(By.NAME,"DateOfBirthMonth"))
month_data = element.options
for month in month_data:
    if month.text =="July":
        month.click()
element = Select(driver.find_element(By.NAME,"DateOfBirthYear"))
element.select_by_index(20)

time.sleep(3)
# import pdb; pdb.set_trace()