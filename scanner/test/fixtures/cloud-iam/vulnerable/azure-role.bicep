resource customRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid('CustomAdmin')
  properties: {
    roleName: 'CustomAdmin'
    permissions: [
      {
        actions: [ 'Microsoft.Authorization/*' ]
        notActions: []
      }
    ]
    assignableScopes: [
      '/subscriptions/00000000-0000-0000-0000-000000000000'
    ]
  }
}
