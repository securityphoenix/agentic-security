// Apollo client calling the `user` query.
import { gql, useQuery } from '@apollo/client';

const GET_USER = gql`
  query GetUser($id: ID!) {
    user(id: $id) {
      id
      name
    }
  }
`;

export function User({ id }) {
  const { data } = useQuery(GET_USER, { variables: { id } });
  return data;
}
