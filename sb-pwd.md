# How to obtain your Slingbox admin password?

## Using the Identity Endpoint

*Method confirmed on: 12/1/2022*

You can obtain this by using [Postman](https://www.postman.com/downloads/) to call 2 APIs in order to get the memberslingbox info. This process is detailed below:

1. Invoke the Identity endpoint to obtain your `member-id` and `username`.

    ```php
    curl --location --request POST 'https://secure.sling.com/slingaccounts/rest/v3/identitypoint' \
    --header 'Content-Type: application x-www-form-urlencoded' \
    --data-urlencode 'context=SLINGIT_PORTAL' \
    --data-urlencode 'policy_code=MAS' \
    --data-urlencode 'email_address=my-sbaccount@me.com' \
    --data-urlencode 'password=my-password'
    ```

    Sample Response:

    ```xml
    <identitypoint>
        <identity>5749057</identity>
        <ticket>6fe2d62a-fa5b-47b8-96dc-074ac5e15766-prod</ticket>
    </identitypoint>
    ```

    Postman reference:

    > ![](./assets/img/sc-iden-endp.png)

    In Postman > Body tab:

    - Select `x-www-form-urlencoded`.
    - Enter following key / values:

        | key	| value |
        | ------ | ------ |
        | context	| SLINGIT_PORTAL |
        | policy_code	| MAS |
        | email_address	| {user-email} |
        | password	| {user-password} |

    Hit send. If it worked, you should get a `200 OK` with JSON response. Save the identity and ticket from response, you will need those for the next call.

2. Obtain your user and admin password:

    ```php
    curl --location --request GET 'https://secure.sling.com/slingaccounts/rest/v5/member/8239057/device/slingboxes' \
    --header 'Content-Type: application/json' \
    --header 'Authorization: Basic GGbZlNEJ2MmEtZmE3Yi00OHR4LTk2OTMtMDc0YWM1ZTc1NzR5LXByb2Q1'
    ```

    Sample response:

    ```xml
    <memberslingboxes>
        <memberslingbox>
            <memberSlingBoxId>8239057</memberSlingBoxId>
            <slingbox>
                <finderId>0F084E4A2950F319D6E6BD7DCB4E4E</finderId>
                <productSignature>000012</productSignature>
            </slingbox>
            <adminPassword>E1:646608a8c13707ae850fecfe20f34d75b97555fcbd3dc3a0a32f14c43b4a05</adminPassword>
            <userPassword>E1:563deba5114b2ee5ea0a41aa76e4ea288879c650bfb9c5faa793f859786d2c0</userPassword>
            <displayName>My Slingbox</displayName>
            <isOwner>true</isOwner>
            <passwordAutoMode>true</passwordAutoMode>
            <lookupByFinderId>true</lookupByFinderId>
            <guestCount>0</guestCount>
        </memberslingbox>
        <size>1</size>
    </memberslingboxes>
    ```

    Postman reference:
    
    > ![](./assets/img/sc-get-pwd.png)
    
    For this call, replace `{member-id}` with the "identity" value from first request:

    https://secure.sling.com/slingaccounts/rest/v5/member/`{member-id}`/device/slingboxes

    - In the Authorization tab, select `Basic Auth`
    - Enter the `ticket` value from first request as the username
        - Leave the password blank.
    - Hit Send

    It should list out your member slingbox JSON, which is a document that contains entries of: `adminPassword`.