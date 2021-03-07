from selenium import webdriver

import requests



if __name__ == '__main__':
	# content = requests.get("https://xsite.singaporetech.edu.sg")
	content = requests.get("https://www.youtube.com")


	# print(content.text)

	with open("test_save.txt", "wb") as f:
		for chunk in content.iter_content(100):
			f.write(chunk)


		f.close()
	# driver = webdriver.Firefox()
	# driver.get("data:text/html;charset=utf-8," + content)