from cornice.resource import resource, view
from pyramid.response import Response

from caliopen.base.user.core import (Contact as CoreContact,
                                     Email as CoreEmail,
                                     IM as CoreIM,
                                     Phone as CorePhone,
                                     SocialIdentity as CoreIdentity,
                                     PublicKey as CorePublicKey,
                                     Organization as CoreOrganization,
                                     PostalAddress as CoreAddress)

from caliopen.base.user.returns import (ReturnContact,
                                        ReturnIndexShortContact,
                                        ReturnAddress, ReturnEmail,
                                        ReturnIM, ReturnPhone,
                                        ReturnOrganization,
                                        ReturnSocialIdentity,
                                        ReturnPublicKey)

from caliopen.base.user.parameters import (NewContact,
                                           Contact as ContactParam)

from caliopen.api.base import Api, make_url
from caliopen.base.exception import NotFound
from caliopen.api.base.exception import ResourceNotFound, ValidationError


@resource(collection_path=make_url('/contacts'),
          path=make_url('/contacts/{contact_id}'))
class Contact(Api):

    """Contact API."""

    def __init__(self, request):
        self.request = request
        self.user = request.authenticated_userid

    @view(renderer='json', permission='authenticated')
    def collection_get(self):
        """Retrieve and search contacts.

        Returns:
            list: list of `ReturnIndexShortContact`

        Raises:
            HTTPBadRequest: input parameters are not valid
        """

        results = CoreContact.find_index(self.user, None,
                                         limit=self.get_limit(),
                                         offset=self.get_offset())
        data = [ReturnIndexShortContact.build(x).serialize()
                for x in results['data']]
        return {'contacts': data, 'total': results['total']}

    @view(renderer='json', permission='authenticated')
    def get(self):
        """Retrieve a contact by its uuid.

        Args:
            contact_id: uuid of contact to retrieve

        Returns:
            ReturnContact: contact retrieved

        Raises:
            HTTPBadRequest: input parameters are not valid
        """
        contact_id = self.request.matchdict.get('contact_id')
        try:
            contact = CoreContact.get(self.user, contact_id)
        except NotFound:
            raise ResourceNotFound('No such contact')
        return {'contacts': ReturnContact.build(contact).serialize()}

    @view(renderer='json', permission='authenticated')
    def collection_post(self):
        """Create a new contact.

        Args:
            `: structure describing contact to create
        Returns:
            `: contact created

        Raises:
            HTTPBadRequest: input parameters are not valid
        """
        data = self.request.json
        contact_param = NewContact(data)
        try:
            contact_param.validate()
        except Exception as exc:
            raise ValidationError(exc)
        contact = CoreContact.create(self.user, contact_param)
        out_contact = ReturnContact.build(contact).serialize()
        return Response(status=201, body={'contacts': out_contact})


class BaseSubContactApi(Api):

    core_class = None
    return_class = None
    namespace = None

    def __init__(self, request):
        self.request = request
        self.user = request.authenticated_userid
        contact_id = self.request.matchdict.get('contact_id')
        self.contact = CoreContact.get(self.user, contact_id)

    @view(renderer='json', permission='authenticated')
    def collection_get(self):
        # XXX define filters from request
        filters = {}
        objs = self.core_class.find_index(self.user, self.contact, filters,
                                          limit=self.get_limit(),
                                          offset=self.get_offset())
        rets = [self.return_class.build(x).serialize() for x in objs['data']]
        return {self.namespace: rets, 'total': objs['total']}


@resource(collection_path=make_url('/contacts/{contact_id}/addresses'),
          path=make_url('/contacts/{contact_id}/addresses/{address_id}'))
class ContactAddress(BaseSubContactApi):

    core_class = CoreAddress
    return_class = ReturnAddress
    namespace = 'addresses'


@resource(collection_path=make_url('/contacts/{contact_id}/emails'),
          path=make_url('/contacts/{contact_id}/emails/{email_id}'))
class ContactEmail(BaseSubContactApi):

    core_class = CoreEmail
    return_class = ReturnEmail
    namespace = 'emails'


@resource(collection_path=make_url('/contacts/{contact_id}/ims'),
          path=make_url('/contacts/{contact_id}/ims/{im_id}'))
class ContactIM(BaseSubContactApi):

    core_class = CoreIM
    return_class = ReturnIM
    namespace = 'ims'


@resource(collection_path=make_url('/contacts/{contact_id}/identities'),
          path=make_url('/contacts/{contact_id}/identities/{identity_id}'))
class ContactSocialIdentity(BaseSubContactApi):

    core_class = CoreIdentity
    return_class = ReturnSocialIdentity
    namespace = 'identities'


@resource(collection_path=make_url('/contacts/{contact_id}/phones'),
          path=make_url('/contacts/{contact_id}/phones/{phone_id}'))
class ContactPhone(BaseSubContactApi):

    core_class = CorePhone
    return_class = ReturnPhone
    namespace = 'phones'


@resource(collection_path=make_url('/contacts/{contact_id}/organizations'),
          path=make_url('/contacts/{contact_id}/organizations/{org_id}'))
class ContactOrganization(BaseSubContactApi):

    core_class = CoreOrganization
    return_class = ReturnOrganization
    namespace = 'organizations'


@resource(collection_path=make_url('/contacts/{contact_id}/keys'),
          path=make_url('/contacts/{contact_id}/keys/{key_id}'))
class ContactPublicKey(BaseSubContactApi):

    core_class = CorePublicKey
    return_class = ReturnPublicKey
    namespace = 'keys'
