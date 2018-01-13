Item Catalog Web App

Nicolas Turner

Project Overview
A basic CRUD application that allows users to create, read, update, and delete items related to an e-commerce store. Users can view items without logging in, but only users who created a category or item are allowed to modify them.

Third-party authentication is implemented using Google or Facebook. Key technolgoies used for this app include Flask, Bootstrap, SQLAlchemy, OAuth, and httplib2.

Requirements to run
Vagrant: https://www.vagrantup.com
Udacity Vagrant file: https://github.com/udacity/fullstack-nanodegree-vm

To Run
1) Launch VM with vagrant up, then vagrant ssh
2) Navigate into catalog_app
3) Run the app: python application.py
4) Navigate via web browser: http://localhost:8000
5) Log in to start creating categories and related items


JSON Endpoints

/catalog.json - JSON of all items in catalog.

/api/v1/categories/<int:category_id>/item/<int:catalog_item_id>/JSON - Selected item in the catalog.

/categories/JSON - JSON of all categories in catalog.

IMAGE Credit: 
Please note, the placeholder image for item details was obtained from a royalty free image sharing site with no restrictions for personal and non-commercial use: https://www.pexels.com/photo/view-of-vintage-camera-325153/