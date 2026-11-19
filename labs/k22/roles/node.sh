# role uzlu: $1 = síť (lan|srv|wan) pro trasy přes směrovač, dál služby (http share db sink client idle)
NET=$1; shift
ip route del default 2>/dev/null
case $NET in
  lan) ip route add default via 10.77.1.254 ;;
  srv) ip route add 10.77.1.0/24 via 10.77.2.254; ip route add 10.77.9.0/24 via 10.77.2.254 ;;
  wan) ip route add 10.77.1.0/24 via 10.77.9.254; ip route add 10.77.2.0/24 via 10.77.9.254 ;;
esac
exec python3 /lab/node.py "$@"
