import { useState, useEffect } from 'react'
import './App.css'

type data_type = {
  Hello: string
}

const App = () => {
  const [data, setData] = useState<data_type>();
  const [loading, setLoading] = useState<boolean>(false);

  const fetchApi = async() => {
    setLoading(true);
    await fetch("http://localhost:8081/")
      .then((res) => res.json())
      .then((d) => setData(d))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    fetchApi();
  }, []);

  return (
    <>
      {loading? (
        <p>Now loading</p>
      ):(
        <p>{data?.Hello}</p>
      )}
    </>
  )
}

export default App
